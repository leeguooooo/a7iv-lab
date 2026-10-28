#include "cube_input.h"
#include <float.h>
#include <math.h>
#include <string.h>

struct token { const char *p; size_t n; };
static int space(char c) { return c==' ' || c=='\t' || c=='\r' || c=='\v' || c=='\f'; }
static int equal(struct token t, const char *s) {
    return t.n==strlen(s) && !memcmp(t.p,s,t.n);
}
static struct token next(const char **p, const char *end) {
    struct token t;
    while (*p<end && space(**p)) ++*p;
    t.p=*p;
    while (*p<end && !space(**p) && **p!='#') ++*p;
    t.n=(size_t)(*p-t.p);
    return t;
}
static int exhausted(const char *p, const char *end) {
    while (p<end && space(*p)) ++p;
    return p==end || *p=='#';
}

/* Locale-independent decimal conversion. No strtod/sscanf global locale,
 * allocation, external math function or firmware import address required. */
static int decimal(struct token t, double *out) {
    size_t i=0; int sign=1, digits=0, fraction=0, kept=0, extra=0;
    int exponent=0, exponent_sign=1, exp_digits=0;
    double value=0, scale=10;
    if (!t.n || t.n>128) return 0;
    if (t.p[i]=='+' || t.p[i]=='-') { if (t.p[i++]=='-') sign=-1; }
    while (i<t.n && t.p[i]>='0' && t.p[i]<='9') {
        int d=t.p[i++]-'0'; ++digits;
        if (kept<18) { if (kept || d) { value=value*10+d; ++kept; } } else ++extra;
    }
    if (i<t.n && t.p[i]=='.') {
        ++i;
        while (i<t.n && t.p[i]>='0' && t.p[i]<='9') {
            int d=t.p[i++]-'0'; ++digits; ++fraction;
            if (kept<18) { if (kept || d) { value=value*10+d; ++kept; } } else ++extra;
        }
    }
    if (!digits) return 0;
    if (i<t.n && (t.p[i]=='e' || t.p[i]=='E')) {
        ++i;
        if (i<t.n && (t.p[i]=='+' || t.p[i]=='-')) {
            if (t.p[i++]=='-') exponent_sign=-1;
        }
        while (i<t.n && t.p[i]>='0' && t.p[i]<='9') {
            int d=t.p[i++]-'0'; ++exp_digits;
            if (exponent>1000) return 0;
            exponent=exponent*10+d;
        }
        if (!exp_digits) return 0;
    }
    if (i!=t.n) return 0;
    exponent=exponent_sign*exponent-fraction+extra;
    if (!value) { *out=sign*0.0; return 1; }
    /* The mantissa has at most 18 digits. Smaller exponents cannot produce a
     * nonzero float; reject before a scale can overflow and hide underflow. */
    if (exponent>308 || exponent < -64) return 0;
    unsigned power=(unsigned)(exponent<0 ? -exponent : exponent);
    while (power) {
        if (power&1u) value=exponent<0 ? value/scale : value*scale;
        power>>=1;
        if (power) scale*=scale;
    }
    value*=sign;
    if (!isfinite(value) || value>FLT_MAX || value < -FLT_MAX || (value!=0 && (float)value==0)) return 0;
    *out=value;
    return 1;
}
static int triple(const char **p, const char *end, double values[3]) {
    for (int c=0;c<3;++c) if (!decimal(next(p,end),values+c)) return 0;
    return exhausted(*p,end);
}
static int title(const char *p, const char *end) {
    while (p<end && space(*p)) ++p;
    if (p==end || *p++!='"') return 0;
    while (p<end) {
        if (*p=='"') return exhausted(p+1,end);
        if ((unsigned char)*p<32) return 0;
        if (*p++=='\\') {
            if (p==end || (*p!='"' && *p!='\\')) return 0;
            ++p;
        }
    }
    return 0;
}
static int fail(struct camera_cube_error *e, int code, uint32_t line) {
    if (e) { e->code=(uint32_t)code; e->line=line; }
    return code;
}

int camera_cube_parse(const char *text, size_t bytes, float *temporary,
                      size_t capacity, struct camera_cube_info *result,
                      struct camera_cube_error *error) {
    struct camera_cube_info info={0};
    uint32_t line=0, seen_size=0, seen_min=0, seen_max=0, seen_title=0;
    size_t cursor=0, expected=0;
    if (!text || !temporary || !result) return fail(error,CAMERA_CUBE_ARGUMENT,0);
    if (!bytes || bytes>CAMERA_CUBE_MAX_BYTES) return fail(error,CAMERA_CUBE_LIMIT,0);
    if (memchr(text,0,bytes)) return fail(error,CAMERA_CUBE_SYNTAX,0);
    for (int c=0;c<3;++c) info.domain_max[c]=1;
    if (bytes>=3 && !memcmp(text,"\xef\xbb\xbf",3)) cursor=3;
    while (cursor<bytes) {
        size_t start=cursor;
        while (cursor<bytes && text[cursor]!='\n') ++cursor;
        const char *p=text+start, *end=text+cursor;
        if (cursor<bytes) ++cursor;
        ++line;
        if ((size_t)(end-p)>4096) return fail(error,CAMERA_CUBE_LIMIT,line);
        if (exhausted(p,end)) continue;
        struct token first=next(&p,end);
        if (equal(first,"TITLE")) {
            if (seen_title++ || info.rows || !title(p,end)) return fail(error,CAMERA_CUBE_SYNTAX,line);
        } else if (equal(first,"LUT_3D_SIZE")) {
            struct token n=next(&p,end); unsigned size=0;
            if (seen_size++ || info.rows || !n.n || n.n>2 || !exhausted(p,end)) return fail(error,CAMERA_CUBE_SIZE,line);
            for (size_t i=0;i<n.n;++i) {
                if (n.p[i]<'0' || n.p[i]>'9') return fail(error,CAMERA_CUBE_SIZE,line);
                size=size*10+(unsigned)(n.p[i]-'0');
            }
            if (size<2 || size>CAMERA_CUBE_MAX_SIZE) return fail(error,CAMERA_CUBE_SIZE,line);
            info.size=size; expected=(size_t)size*size*size;
            if (capacity<expected*3) return fail(error,CAMERA_CUBE_CAPACITY,line);
        } else if (equal(first,"DOMAIN_MIN") || equal(first,"DOMAIN_MAX")) {
            int low=equal(first,"DOMAIN_MIN");
            uint32_t *seen=low ? &seen_min : &seen_max;
            if ((*seen)++ || info.rows || !triple(&p,end,low ? info.domain_min : info.domain_max)) return fail(error,CAMERA_CUBE_DOMAIN,line);
            info.explicit_domain=1;
        } else if (equal(first,"LUT_3D_INPUT_RANGE")) {
            double lo,hi;
            if (seen_min || seen_max || info.rows || !decimal(next(&p,end),&lo) || !decimal(next(&p,end),&hi) || !exhausted(p,end)) return fail(error,CAMERA_CUBE_DOMAIN,line);
            for (int c=0;c<3;++c) { info.domain_min[c]=lo; info.domain_max[c]=hi; }
            seen_min=seen_max=1; info.explicit_domain=1;
        } else {
            double values[3];
            if ((first.p[0]>='A' && first.p[0]<='Z') || (first.p[0]>='a' && first.p[0]<='z')) return fail(error,CAMERA_CUBE_DIRECTIVE,line);
            if (!seen_size || info.rows>=expected) return fail(error,CAMERA_CUBE_ROWS,line);
            p=first.p;
            if (!triple(&p,end,values)) return fail(error,CAMERA_CUBE_NUMBER,line);
            for (int c=0;c<3;++c) {
                temporary[(size_t)info.rows*3+c]=(float)values[c];
                if (!info.rows || values[c]<info.output_min[c]) info.output_min[c]=values[c];
                if (!info.rows || values[c]>info.output_max[c]) info.output_max[c]=values[c];
            }
            ++info.rows;
        }
    }
    if (!seen_size || info.rows!=expected) return fail(error,CAMERA_CUBE_ROWS,line);
    for (int c=0;c<3;++c) if (!(info.domain_max[c]>info.domain_min[c])) return fail(error,CAMERA_CUBE_DOMAIN,line);
    *result=info;
    if (error) { error->code=0; error->line=0; }
    return CAMERA_CUBE_OK;
}

static int valid_grid(const struct camera_cube_info *info, size_t count) {
    if (!info) return CAMERA_CUBE_ARGUMENT;
    if (info->size<2 || info->size>CAMERA_CUBE_MAX_SIZE) return CAMERA_CUBE_SIZE;
    size_t rows=(size_t)info->size*info->size*info->size;
    if (info->rows!=rows) return CAMERA_CUBE_ROWS;
    if (count<rows*3) return CAMERA_CUBE_CAPACITY;
    for (int c=0;c<3;++c) {
        double lo=info->domain_min[c], hi=info->domain_max[c];
        if (!isfinite(lo) || !isfinite(hi) || !(hi>lo) || !isfinite(hi-lo)) return CAMERA_CUBE_DOMAIN;
    }
    return CAMERA_CUBE_OK;
}

static int sample_grid(const struct camera_cube_info *info, const float *values,
                       const double rgb[3], enum camera_cube_bounds bounds,
                       double output[3], uint32_t *clamped) {
    unsigned low[3]; double fraction[3], result[3]={0};
    uint32_t outside=0; unsigned n=info->size;
    for (int c=0;c<3;++c) {
        double value=rgb[c], lo=info->domain_min[c], hi=info->domain_max[c];
        if (!isfinite(value)) return CAMERA_CUBE_NUMBER;
        if (value<lo || value>hi) {
            if (bounds!=CAMERA_CUBE_CLAMP_OUTSIDE) return CAMERA_CUBE_DOMAIN;
            outside=1; value=value<lo ? lo : hi;
        }
        double coordinate=(value-lo)/(hi-lo)*(n-1);
        /* Protect endpoint indexing against final arithmetic rounding. */
        if (coordinate<0) coordinate=0;
        if (coordinate>n-1) coordinate=n-1;
        low[c]=(unsigned)coordinate;
        if (low[c]>=n-1) low[c]=n-2;
        fraction[c]=coordinate-low[c];
    }
    for (unsigned b=0;b<2;++b) for (unsigned g=0;g<2;++g) for (unsigned r=0;r<2;++r) {
        size_t index=(((size_t)(low[2]+b)*n+low[1]+g)*n+low[0]+r)*3;
        double weight=(r ? fraction[0] : 1-fraction[0])*
                      (g ? fraction[1] : 1-fraction[1])*
                      (b ? fraction[2] : 1-fraction[2]);
        for (int c=0;c<3;++c) {
            double value=values[index+c];
            if (!isfinite(value)) return CAMERA_CUBE_NUMBER;
            result[c]+=weight*value;
        }
    }
    for (int c=0;c<3;++c) if (!isfinite(result[c])) return CAMERA_CUBE_NUMBER;
    memcpy(output,result,sizeof(result));
    if (clamped) *clamped=outside;
    return CAMERA_CUBE_OK;
}

int camera_cube_sample(const struct camera_cube_info *info, const float *values,
                       size_t count, const double rgb[3],
                       enum camera_cube_bounds bounds, double output[3]) {
    if (!values || !rgb || !output || (bounds!=CAMERA_CUBE_REJECT_OUTSIDE && bounds!=CAMERA_CUBE_CLAMP_OUTSIDE)) return CAMERA_CUBE_ARGUMENT;
    int status=valid_grid(info,count);
    if (status) return status;
    return sample_grid(info,values,rgb,bounds,output,0);
}

static int overlapping(const void *a, size_t an, const void *b, size_t bn) {
    uintptr_t aa=(uintptr_t)a, bb=(uintptr_t)b;
    return aa<=bb ? bb-aa<an : aa-bb<bn;
}

int camera_cube_resample(const struct camera_cube_info *info, const float *values,
                         size_t count, uint32_t target,
                         enum camera_cube_bounds bounds, float *temporary,
                         size_t capacity, struct camera_cube_info *result,
                         uint32_t *clamped_nodes) {
    struct camera_cube_info output={0};
    uint32_t clamped=0;
    if (!values || !temporary || !result || (bounds!=CAMERA_CUBE_REJECT_OUTSIDE && bounds!=CAMERA_CUBE_CLAMP_OUTSIDE)) return CAMERA_CUBE_ARGUMENT;
    int status=valid_grid(info,count);
    if (status) return status;
    if (target!=17 && target!=33) return CAMERA_CUBE_SIZE;
    size_t source_count=(size_t)info->rows*3, rows=(size_t)target*target*target;
    if (capacity<rows*3) return CAMERA_CUBE_CAPACITY;
    if (overlapping(values,source_count*sizeof(float),temporary,rows*3*sizeof(float))) return CAMERA_CUBE_ARGUMENT;
    for (size_t i=0;i<source_count;++i) if (!isfinite(values[i])) return CAMERA_CUBE_NUMBER;
    /* A rejected range must not partially overwrite the temporary grid. */
    if (bounds==CAMERA_CUBE_REJECT_OUTSIDE) for (int c=0;c<3;++c) {
        if (info->domain_min[c]>0 || info->domain_max[c]<1) return CAMERA_CUBE_DOMAIN;
    }
    output.size=target; output.rows=(uint32_t)rows;
    for (int c=0;c<3;++c) output.domain_max[c]=1;
    for (uint32_t b=0;b<target;++b) for (uint32_t g=0;g<target;++g) for (uint32_t r=0;r<target;++r) {
        double rgb[3]={(double)r/(target-1),(double)g/(target-1),(double)b/(target-1)}, sampled[3];
        uint32_t node_clamped;
        status=sample_grid(info,values,rgb,bounds,sampled,&node_clamped);
        if (status) return status;
        clamped+=node_clamped;
        size_t row=((size_t)b*target+g)*target+r;
        for (int c=0;c<3;++c) {
            float value=(float)sampled[c];
            if (!isfinite(value)) return CAMERA_CUBE_NUMBER;
            temporary[row*3+c]=value;
            if (!row || value<output.output_min[c]) output.output_min[c]=value;
            if (!row || value>output.output_max[c]) output.output_max[c]=value;
        }
    }
    *result=output;
    if (clamped_nodes) *clamped_nodes=clamped;
    return CAMERA_CUBE_OK;
}

int camera_cube_pack_ap_integer(const struct camera_cube_info *info,
                                const float *values, size_t count,
                                enum camera_cube_quantization policy,
                                unsigned char *temporary, size_t capacity,
                                uint32_t *saturated_components) {
    const double max_value=65535.0/8192.0;
    uint32_t saturated=0;
    if (!values || !temporary || (policy!=CAMERA_CUBE_REJECT_UNREPRESENTABLE && policy!=CAMERA_CUBE_SATURATE_Q13)) return CAMERA_CUBE_ARGUMENT;
    int status=valid_grid(info,count);
    if (status) return status;
    unsigned n=info->size;
    if (n!=17 && n!=33) return CAMERA_CUBE_SIZE;
    if (capacity<CAMERA_CUBE_AP_INTEGER_BYTES) return CAMERA_CUBE_CAPACITY;
    for (int c=0;c<3;++c) if (info->domain_min[c]!=0 || info->domain_max[c]!=1) return CAMERA_CUBE_DOMAIN;
    size_t source_count=(size_t)info->rows*3;
    if (overlapping(values,source_count*sizeof(float),temporary,CAMERA_CUBE_AP_INTEGER_BYTES)) return CAMERA_CUBE_ARGUMENT;
    for (size_t i=0;i<source_count;++i) {
        double value=values[i];
        if (!isfinite(value)) return CAMERA_CUBE_NUMBER;
        if (policy==CAMERA_CUBE_REJECT_UNREPRESENTABLE && (value<0 || value>max_value)) return CAMERA_CUBE_NUMBER;
    }
    memset(temporary,0,CAMERA_CUBE_AP_INTEGER_BYTES);
    unsigned stride=(n-1)/16;
    for (unsigned r=0;r<17;++r) for (unsigned g=0;g<17;++g) for (unsigned b=0;b<17;++b) {
        size_t source=(((size_t)b*stride*n+g*stride)*n+r*stride)*3;
        unsigned bank=(r&1u)*4+(g&1u)*2+(b&1u);
        unsigned index=(r/2)*100+(g/2)*10+b/2;
        for (unsigned c=0;c<3;++c) {
            double value=values[source+c];
            if (value<0 || value>max_value) {
                ++saturated; value=value<0 ? 0 : max_value;
            }
            uint32_t encoded=(uint32_t)(value*8192+0.5);
            size_t offset=((size_t)c*8000+bank*1000+index)*2;
            temporary[offset]=(unsigned char)encoded;
            temporary[offset+1]=(unsigned char)(encoded>>8);
        }
    }
    if (saturated_components) *saturated_components=saturated;
    return CAMERA_CUBE_OK;
}
