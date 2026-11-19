import gzip
import os
import tempfile
import unittest

import helpers  # noqa: F401
from mavirank_collector.files import commit, discover, finish_old, plan_units, read_lines


def consume(files, paths, now=1000.0, warnings=None):
    """One pass: plan, read everything, commit like a successful send."""
    out = []
    for unit in plan_units(files, paths, now, (warnings if warnings is not None else []).append):
        end = unit.start
        for text, _b, e in read_lines(unit.path, unit.start):
            out.append(text)
            end = e
        commit(files, unit, end)
        if unit.slot == "old":
            finish_old(files, unit)
    return out


class FilesTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name
        self.log = os.path.join(self.dir, "access.log")

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, path, text, mode="a"):
        with open(path, mode, encoding="utf-8") as fh:
            fh.write(text)

    def test_incremental_and_partial_line(self):
        files = {}
        self.write(self.log, "a\nb\npart")
        self.assertEqual(consume(files, [(self.log, "access")]), ["a", "b"])
        self.write(self.log, "ial\nc\n")
        self.assertEqual(consume(files, [(self.log, "access")]), ["partial", "c"])
        self.assertEqual(consume(files, [(self.log, "access")]), [])
        self.assertEqual(files[self.log]["cur"]["offset"], os.path.getsize(self.log))

    def test_rename_rotation_reads_rest_of_old_file(self):
        files = {}
        self.write(self.log, "1\n2\n")
        consume(files, [(self.log, "access")])
        self.write(self.log, "3\n")  # written after the last run, before rotation
        os.rename(self.log, self.log + ".1")
        self.write(self.log, "4\n", "w")
        self.assertEqual(consume(files, [(self.log, "access")]), ["3", "4"])
        self.assertIsNone(files[self.log]["old"])
        self.assertEqual(consume(files, [(self.log, "access")]), [])

    def test_dateext_rotation_found_by_inode(self):
        files = {}
        self.write(self.log, "1\n")
        consume(files, [(self.log, "access")])
        self.write(self.log, "2\n")
        os.rename(self.log, self.log + "-20261111")
        self.write(self.log, "3\n", "w")
        self.assertEqual(consume(files, [(self.log, "access")]), ["2", "3"])

    def test_rotation_into_gzip_loses_only_unread_tail(self):
        files = {}
        self.write(self.log, "1\n")
        consume(files, [(self.log, "access")])
        with open(self.log, "rb") as src, gzip.open(self.log + ".1.gz", "wb") as dst:
            dst.write(src.read())
        os.unlink(self.log)
        self.write(self.log, "2\n", "w")
        warnings = []
        self.assertEqual(consume(files, [(self.log, "access")], warnings=warnings), ["2"])
        # either the rotated copy is missing, or the filesystem reused the inode (fingerprint changed)
        self.assertTrue(any("not found" in w or "replaced" in w for w in warnings), warnings)

    def test_copytruncate_restarts(self):
        files = {}
        self.write(self.log, "1\n2\n3\n")
        consume(files, [(self.log, "access")])
        with open(self.log, "w", encoding="utf-8") as fh:
            fh.truncate(0)
            fh.write("4\n")
        self.assertEqual(consume(files, [(self.log, "access")]), ["4"])

    def test_replaced_head_detected_by_fingerprint(self):
        files = {}
        self.write(self.log, "aaaa\n")
        consume(files, [(self.log, "access")])
        with open(self.log, "r+", encoding="utf-8") as fh:  # same inode, same size class, new content
            fh.write("bbbb\ncccc\n")
        self.assertEqual(consume(files, [(self.log, "access")]), ["bbbb", "cccc"])

    def test_first_sight_reads_rotated_copy(self):
        self.write(self.log + ".1", "old\n")
        self.write(self.log, "new\n")
        self.assertEqual(consume({}, [(self.log, "access")]), ["old", "new"])

    def test_discover_skips_compressed_and_numbered_rotations(self):
        for name in ("access.log", "access.log.1", "access.log.2.gz", "access.log.3", "other.log", "x.log.gz"):
            self.write(os.path.join(self.dir, name), "x\n")
        found = [os.path.basename(p) for p in discover([os.path.join(self.dir, "*.log*")])]
        self.assertEqual(found, ["access.log", "other.log"])
        self.assertEqual(discover([os.path.join(self.dir, "missing.log")]), [])

    def test_symlink_read_once(self):
        self.write(self.log, "1\n")
        link = os.path.join(self.dir, "link.log")
        os.symlink(self.log, link)
        self.assertEqual(consume({}, [(self.log, "access"), (link, "access")]), ["1"])

    def test_overlong_line_is_skipped(self):
        from mavirank_collector import files as fm
        self.write(self.log, "x" * (fm.MAX_LINE + 10) + "\nok\n")
        items = list(read_lines(self.log, 0))
        self.assertEqual([t for t, _, _ in items], [None, "ok"])
        self.assertEqual(items[-1][2], os.path.getsize(self.log))

    def test_entries_pruned_after_a_week(self):
        files = {}
        self.write(self.log, "1\n")
        consume(files, [(self.log, "access")], now=1000.0)
        plan_units(files, [], 1000.0 + 8 * 86400, lambda m: None)
        self.assertEqual(files, {})


if __name__ == "__main__":
    unittest.main()
