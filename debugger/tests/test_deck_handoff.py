import tempfile
import unittest
from pathlib import Path
import zipfile

from scripts.deck_handoff import collect, choose_ghidra


class DeckHandoffTests(unittest.TestCase):
    def test_results_exclude_game_files_and_symlinks(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            results = root / '.local/deck-results'
            results.mkdir(parents=True)
            (results/'doctor.json').write_text('{"architecture":"x86_64"}')
            (results/'game.gbc').write_bytes(b'private game data')
            (results/'state.sbs').write_bytes(b'private checkpoint')
            private = root/'private.txt'
            private.write_text('private data')
            (root/'NOTES.txt').symlink_to(private)
            output = collect(root)
            self.assertEqual(output.parent, root / ".local/results")
            with zipfile.ZipFile(output) as archive:
                self.assertEqual(set(archive.namelist()), {'GhiGBC-results/doctor.json', 'GhiGBC-results/README.txt'})
                self.assertNotIn(b'private data', b''.join(archive.read(name) for name in archive.namelist()))

    def test_wrong_ghidra_version_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root/'Ghidra').mkdir()
            props = root/'Ghidra/application.properties'
            props.write_text('application.version=12.1.2\n')
            with self.assertRaisesRegex(RuntimeError, '12.1.3 is required'):
                choose_ghidra(str(root))
            props.write_text('application.version=12.1.3\n')
            self.assertEqual(choose_ghidra(str(root)), root.resolve())
