import unittest

from uac_parser.resources import resource_directory, resource_file


class ResourceTests(unittest.TestCase):
    def test_rules_and_assets_resolve(self) -> None:
        self.assertTrue(resource_file("rules", "tagging_registry.yml").is_file())
        self.assertTrue(resource_file("assets", "tracequarry-lockup.svg").is_file())
        self.assertTrue(resource_file("assets", "cep-mark.svg").is_file())
        self.assertTrue(resource_directory("assets").is_dir())

    def test_unsafe_resource_names_are_rejected(self) -> None:
        with self.assertRaises(ValueError):
            resource_file("assets", "../LICENSE")
