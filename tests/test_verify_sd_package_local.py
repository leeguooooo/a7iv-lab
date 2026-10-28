import pytest

from verify_sd_package_local import verify_backup_coverage


def backup_members():
    return {**{f"0110_backup/template{i}.bin": (i, 100) for i in range(32)},
            "0110_backup/MainDest.txt": (33, 32), "unrelated/member": (34, 1)}


def test_complete_manifest_including_main_destination():
    members = backup_members()
    verify_backup_coverage(members, [name for name in members if name.startswith("0110_backup/")])


@pytest.mark.parametrize("missing", ["0110_backup/MainDest.txt", "0110_backup/template7.bin"])
def test_missing_crc_entry_rejected(missing):
    members = backup_members()
    checked = [name for name in members if name.startswith("0110_backup/") and name != missing]
    with pytest.raises(ValueError, match="Incomplete"):
        verify_backup_coverage(members, checked)


def test_partial_template_set_rejected_even_with_matching_crc_rows():
    members = backup_members()
    del members["0110_backup/template7.bin"]
    with pytest.raises(ValueError, match="32 backup templates"):
        verify_backup_coverage(members, [name for name in members if name.startswith("0110_backup/")])


def test_duplicate_crc_row_rejected():
    members = backup_members()
    checked = [name for name in members if name.startswith("0110_backup/")]
    with pytest.raises(ValueError, match="Duplicate"):
        verify_backup_coverage(members, checked + checked[:1])
