import os
import shutil
import logging

from .parsers import parse_github_channels, parse_asset_packs
from .models import *
from .settings import settings


class RepositoryIndex:
    index: dict
    indexer_github: IndexerGithub

    def __init__(
        self,
        directory: str,
        github_token: str,
        github_repo: str,
        github_org: str,
        file_parser: FileParser = FileParser,
    ):
        self.index = Index().dict()
        self.indexer_github = IndexerGithub()
        self.indexer_github.login(github_token, github_repo, github_org)
        self.directory = directory
        self.file_parser = file_parser

    def delete_empty_directories(self):
        """
        A method for cleaning directories that are empty
        Returns:
            Nothing
        """
        main_dir = os.path.join(settings.files_dir, self.directory)
        for cur in os.listdir(main_dir):
            if cur.startswith("."):
                continue
            cur_dir = os.path.join(main_dir, cur)
            dir_content = os.listdir(cur_dir)
            if len(dir_content) > 0:
                continue
            shutil.rmtree(cur_dir)
            logging.info(f"Deleting {cur_dir}")

    def delete_unlinked_directories(self):
        """
        A method for cleaning directories that do not match
        branches/releases in the repository
        Args:
            Nothing

        Returns:
            Nothing
        """
        main_dir = os.path.join(settings.files_dir, self.directory)
        for root, dirs, files in os.walk(main_dir):
            if len(files) == 0:
                continue
            # skip .DS_store files
            if len(files) == 1 and files[0].startswith("."):
                continue
            cur_dir = root.split(main_dir + "/")[1]
            if self.indexer_github.is_release_exist(cur_dir):
                continue
            if self.indexer_github.is_tag_exist(cur_dir):
                continue
            if self.indexer_github.is_branch_exist(cur_dir):
                continue
            shutil.rmtree(os.path.join(main_dir, cur_dir))
            logging.info(f"Deleting {cur_dir}")

    def reindex(self):
        """
        Method for starting reindexing. We get three channels - dev, release
        from the main repository in the git. We run through all 3 channels,
        each channel has different versions inside. We create models for all
        versions and stuff them with the path to the artifacts.

        At the end of reindexing, all unnecessary branches and
        empty directories are cleared

        Returns:
            Nothing
        """
        try:
            self.indexer_github.sync_info()
            self.index = parse_github_channels(
                self.directory, self.file_parser, self.indexer_github
            )
            logging.info(f"{self.directory} reindex OK")
            self.delete_unlinked_directories()
            self.delete_empty_directories()
        except Exception as e:
            logging.error(f"{self.directory} reindex failed")
            logging.exception(e)
            raise e

    def get_branch_file_names(self: str, branch: str) -> list[str]:
        """
        A method to get a list of file names in the specified branch
        Args:
            branch: Branch name

        Returns:
            The list of file names
        """
        branch_path = os.path.join(settings.files_dir, self.directory, branch)
        if not os.path.isdir(branch_path):
            raise FileNotFoundError("Branch not found!")
        files = os.listdir(branch_path)
        return filter(lambda file: not file.startswith("."), files)

    def get_file_from_latest_version(
        self: str, channel: str, target: str, file_type: str
    ) -> str:
        """
        A method to get a file in the latest version of the
        current directory by its target and type
        Args:
            channel: Channel type (release, dev)
            target: Operating System (linux, mac, win)
            file_type: File Type

        Returns:
            String URL of file`s location
        """
        target = target.replace("-", "/")
        try:
            channels = self.index["channels"]
            current_channel = next(
                filter(lambda c: c.get("id") == channel, channels), None
            )

            if current_channel is None:
                valueerr_msg = f"Channel `{channel}` not found!"
                logging.exception(valueerr_msg)
                raise ValueError(valueerr_msg)

            latest_version = current_channel.get("versions")[0]
            latest_version_file = next(
                filter(
                    lambda c: c.get("target") == target and c.get("type") == file_type,
                    latest_version.get("files"),
                )
            )
            return latest_version_file.get("url")
        except Exception as e:
            logging.exception(e)
            raise e

    def get_file_path(self: str, channel: str, file_name: str) -> str:
        """
        A method to get a specific file by name in the specified channel
        Args:
            channel: Channel type (release, dev)
            file_name: File Name

        Returns:
            The file path
        """
        file_path = os.path.join(settings.files_dir, self.directory, channel, file_name)
        if not os.path.isfile(file_path):
            raise FileNotFoundError("File not found, try a newer link!")
        return file_path


class PacksCatalog:
    index: dict

    def __init__(
        self,
        directory: str,
        pack_parser: PackParser = PackParser,
    ):
        self.index = Catalog().dict()
        self.directory = directory
        self.pack_parser = pack_parser

    def delete_empty_directories(self):
        """
        A method for cleaning directories that are empty
        Returns:
            Nothing
        """
        main_dir = os.path.join(settings.files_dir, self.directory)
        for cur in os.listdir(main_dir):
            cur_dir = os.path.join(main_dir, cur)
            if cur.startswith(".") or not os.path.isdir(cur_dir):
                continue
            dir_content = os.listdir(cur_dir)
            if len(dir_content) > 0:
                continue
            shutil.rmtree(cur_dir)
            logging.info(f"Deleting {cur_dir}")

    def reindex(self):
        """
        Method for starting reindexing. We get available packs from disk
        and parse them for metadata, previews and artifacts.

        At the end of reindexing, all unnecessary empty directories are cleared

        Returns:
            Nothing
        """
        try:
            self.index = parse_asset_packs(self.directory, self.pack_parser)
            logging.info(f"{self.directory} reindex OK")
            self.delete_empty_directories()
        except Exception as e:
            logging.error(f"{self.directory} reindex failed")
            logging.exception(e)
            raise e

    def get_file_path(self: str, pack: str, file_type: str, file_name: str) -> str:
        """
        A method to get a specific file by type and name in the specified pack
        Args:
            pack: Pack id
            file_type: File Type (download, preview)
            file_name: File Name

        Returns:
            The file path
        """
        file_path = os.path.join(
            settings.files_dir, self.directory, pack, file_type, file_name
        )
        if file_type not in ("download", "preview") or not os.path.isfile(file_path):
            raise FileNotFoundError("File not found, try a newer link!")
        return file_path


indexes = {
    "firmware": RepositoryIndex(
        directory="firmware",
        github_token=settings.firmware_github_token,
        github_repo=settings.firmware_github_repo,
        github_org=settings.github_org,
    ),
    "asset-packs": PacksCatalog(
        directory="asset-packs",
    ),
}

raw_file_upload_directories = []
