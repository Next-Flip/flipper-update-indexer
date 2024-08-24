import os
import logging
import copy

from .models import *
from .channels import *
from .settings import settings


def add_files_to_version(
    version: Version, file_parser: FileParser, main_dir: str, сhannel_dir: str
) -> Version:
    """
    Method for adding a new artifact model to the selected version
    Args:
        version:
        file_parser:
        main_dir:
        сhannel_dir:

    Returns:
        Modified model version in which the file model was added
    """
    directory_path = os.path.join(settings.files_dir, main_dir, сhannel_dir)

    if not os.path.isdir(directory_path):
        os.mkdir(directory_path)

    latest_version = None
    for entry in sorted(
        os.scandir(directory_path), key=lambda e: e.stat().st_mtime, reverse=True
    ):
        cur = entry.name
        # skip .DS_store files
        if cur.startswith("."):
            continue
        parsed_file = file_parser()
        try:
            parsed_file.parse(cur)
        except Exception as e:
            logging.exception(e)
            continue
        if latest_version is None:
            match = file_parser.regex.match(cur)
            latest_version = "mntm-" + match.group(3)
            # Is not a release number
            if not version.version.startswith("mntm-"):
                # Get commit sha at the end
                version.version = latest_version.split("-")[-1]
                if version.version in version.changelog:
                    pos = version.changelog.find(version.version)
                    pos = version.changelog.rfind("\n", 0, pos)
                    version.changelog = version.changelog[pos + 1 :]
        elif latest_version not in cur:
            continue
        version.add_file(
            VersionFile(
                url=os.path.join(settings.base_url, main_dir, сhannel_dir, cur),
                target=parsed_file.target,
                type=parsed_file.type,
                sha256=parsed_file.getSHA256(os.path.join(directory_path, cur)),
            )
        )
    return version


def parse_dev_channel(
    channel: Channel,
    directory: str,
    file_parser: FileParser,
    indexer_github: IndexerGithub,
    branch: str,
) -> Channel:
    """
    Method for creating a new version with a file
    and adding it to the dev channel
    Args:
        channel: Channel model (-> dev)
        directory: Save directory
        file_parser: The method by which the file piercing will take place (FileParser)

    Returns:
        New channel with added version
    """
    version = indexer_github.get_dev_version(branch)
    version = add_files_to_version(version, file_parser, directory, branch)
    channel.add_version(version)
    return channel


def parse_release_channel(
    channel: Channel,
    directory: str,
    file_parser: FileParser,
    indexer_github: IndexerGithub,
) -> Channel:
    """
    Method for creating a new version with a file
    and adding it to the release channel
    Args:
        channel: Channel model (-> release)
        directory: Save directory
        file_parser: The method by which the file piercing will take place (FileParser)

    Returns:
        New channel with added version
    """
    version = indexer_github.get_release_version()
    if version:
        version = add_files_to_version(version, file_parser, directory, version.version)
        channel.add_version(version)
    return channel


def parse_github_channels(
    directory: str, file_parser: FileParser, indexer_github: IndexerGithub
) -> dict:
    """
    Method for creating a new index with channels
    Args:
        directory: Save directory
        file_parser: The method by which the file piercing will take place (FileParser)

    Returns:
        New index with added channels
    """
    json = Index()
    json.add_channel(
        parse_dev_channel(
            copy.deepcopy(development_channel),
            directory,
            file_parser,
            indexer_github,
            "dev",
        )
    )
    json.add_channel(
        parse_release_channel(
            copy.deepcopy(release_channel),
            directory,
            file_parser,
            indexer_github,
        )
    )
    for branch in indexer_github.get_unstable_branch_names():
        branch_dir = os.path.join(settings.files_dir, directory, branch)
        if not os.path.isdir(branch_dir) or len(os.listdir(branch_dir)) <= 1:
            continue
        channel = copy.deepcopy(branch_channel)
        channel.id = channel.id.format(branch=branch)
        channel.title = channel.title.format(branch=branch)
        channel.description = channel.description.format(branch=branch)
        json.add_channel(
            parse_dev_channel(channel, directory, file_parser, indexer_github, branch)
        )
    return json.dict()


def parse_asset_packs(directory: str, pack_parser: PackParser) -> dict:
    """
    Method for creating a new catalog with packs
    Args:
        directory: Save directory
        pack_parser: The method by which the pack parsing will take place (PackParser)

    Returns:
        New catalog with added packs
    """
    json = Catalog()
    directory_path = os.path.join(settings.files_dir, directory)

    if not os.path.isdir(directory_path):
        exception_msg = f"Directory {directory_path} not found!"
        logging.exception(exception_msg)
        raise Exception(exception_msg)

    for cur in sorted(os.listdir(directory_path)):
        pack_path = os.path.join(directory_path, cur)
        # skip .DS_store files
        if cur.startswith(".") or not os.path.isdir(pack_path):
            continue
        parsed_pack = pack_parser()
        try:
            pack = parsed_pack.parse(pack_path)
        except Exception as e:
            logging.exception(e)
            continue
        json.add_pack(pack)

    return json.dict()
