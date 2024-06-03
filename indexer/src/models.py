import re
import os
import json
import gzip
import shutil
import tarfile
import hashlib
import logging
import pathlib
from pydantic import BaseModel
from github import Github, Repository
from typing import List, ClassVar

from . import asset_packer
from .settings import settings


class VersionFile(BaseModel):
    url: str
    target: str
    type: str
    sha256: str


class Version(BaseModel):
    version: str
    changelog: str
    timestamp: int
    files: List[VersionFile] = []

    def add_file(self, file: VersionFile) -> None:
        self.files.append(file)


class Channel(BaseModel):
    id: str
    title: str
    description: str
    versions: List[Version] = []

    def add_version(self, version: Version) -> None:
        self.versions.append(version)


class Index(BaseModel):
    channels: List[Channel] = []

    def add_channel(self, channel: Channel) -> None:
        self.channels.append(channel)


class PackFile(BaseModel):
    url: str
    type: str
    sha256: str


class Pack(BaseModel):
    id: str
    name: str
    author: str
    source_url: str = None
    description: str = None
    files: List[PackFile] = []
    preview_urls: List[str] = []

    def add_file(self, file: PackFile) -> None:
        self.files.append(file)

    def add_preview_url(self, preview_url: str) -> None:
        self.preview_urls.append(preview_url)


class Catalog(BaseModel):
    packs: List[Pack] = []

    def add_pack(self, pack: Pack) -> None:
        self.packs.append(pack)


class IndexerGithub:
    __repo: Repository.Repository = None
    __tags: List = []
    __releases: List = []
    __branches: List = []

    def login(self, token: str, repo_name: str, org_name: str) -> None:
        try:
            git = Github(token)
            org = git.get_organization(org_name)
            self.__repo = org.get_repo(repo_name)
        except Exception as e:
            logging.exception(e)
            raise e

    def __get_tags(self) -> None:
        try:
            github_tags = self.__repo.get_tags()
            self.__tags = [x.name for x in github_tags]
        except Exception as e:
            logging.exception(e)
            raise e

    def __get_releases(self) -> None:
        try:
            github_releases = self.__repo.get_releases()
            self.__releases = [x.title for x in github_releases]
        except Exception as e:
            logging.exception(e)
            raise e

    def __get_branches(self) -> None:
        try:
            github_branches = self.__repo.get_branches()
            self.__branches = [x.name for x in github_branches]
        except Exception as e:
            logging.exception(e)
            raise e

    def sync_info(self):
        self.__get_tags()
        self.__get_releases()
        self.__get_branches()

    """
        We need all stuff above (except login) for the delete_unlinked_directories function in repository.py
    """

    def is_branch_exist(self, branch: str) -> bool:
        return branch in self.__branches

    def is_release_exist(self, release: str) -> bool:
        return release in self.__releases

    def is_tag_exist(self, tag: str) -> bool:
        return tag in self.__tags

    def get_dev_version(self) -> Version:
        try:
            commits = self.__repo.get_commits()
            if commits.totalCount == 0:
                exception_msg = f"No commits found in master branch!"
                logging.exception(exception_msg)
                raise Exception(exception_msg)
            last_commit = commits[0]
            changelog = ""
            for commit in commits.get_page(0):
                msg = (
                    commit.commit.message.splitlines()[0]
                    .replace("`", "")
                    .replace("__", "")
                    .replace("**", "")
                )
                msg = msg[:50] + ("..." if len(msg) > 50 else "")
                changelog += f"[`{commit.sha[:8]}`]({commit.html_url}): {msg} - [__{commit.author.login}__](https://github.com/{commit.author.login})\n"
            return Version(
                version=last_commit.sha[:8],
                changelog=changelog,
                timestamp=int(last_commit.commit.author.date.timestamp()),
            )
        except Exception as e:
            logging.exception(e)
            raise e

    def get_release_version(self) -> Version:
        releases = self.__repo.get_releases()
        if releases.totalCount == 0:
            logging.warning(f"No releases found for {self.__repo.full_name}!")
            return None
        try:
            last_release = next(filter(lambda c: not c.prerelease, releases))
            return Version(
                version=last_release.title,
                changelog=last_release.body.split("## 🚀 Changelog", 1)[-1].strip(),
                timestamp=int(last_release.created_at.timestamp()),
            )
        except StopIteration:
            return None


class FileParser(BaseModel):
    target: str = ""
    type: str = ""
    regex: ClassVar[re.Pattern] = re.compile(
        r"^flipper-z-(\w+)-(\w+)-mntm-([0-9]+()?|(dev-\w+))\.(\w+)$"
    )

    def getSHA256(self, filepath: str) -> str:
        with open(filepath, "rb") as file:
            file_bytes = file.read()
            sha256 = hashlib.sha256(file_bytes).hexdigest()
        return sha256

    def parse(self, filename: str) -> None:
        match = self.regex.match(filename)
        if not match:
            exception_msg = f"Unknown file {filename}"
            logging.exception(exception_msg)
            raise Exception(exception_msg)
        self.target = match.group(1)
        self.type = match.group(2) + "_" + match.group(6)


class PackParser(BaseModel):
    GZIP_MODE = "wb"
    GZIP_LEVEL = 9
    TAR_MODE = "w:"
    TAR_FORMAT = tarfile.USTAR_FORMAT
    ENTRY_NAME_MAX_LENGTH = 100

    def getSHA256(self, filepath: str) -> str:
        with open(filepath, "rb") as file:
            file_bytes = file.read()
            sha256 = hashlib.sha256(file_bytes).hexdigest()
        return sha256

    def _rebuild(self, packpath):
        pack_set = pathlib.Path(packpath)
        pack_source = pack_set / "source"
        pack_compiled = pack_set / ".compiled"
        asset_packer.pack(pack_source, pack_compiled, logger=logging.debug)

        pack_zip = (pack_set / "file" / pack_set.name).with_suffix(".zip")
        pack_targz = pack_zip.with_suffix(".tar.gz")
        pack_zip.unlink(missing_ok=True)
        pack_targz.unlink(missing_ok=True)

        shutil.make_archive(pack_zip.with_suffix(""), "zip", pack_compiled)

        with gzip.open(pack_targz, self.GZIP_MODE, compresslevel=self.GZIP_LEVEL) as f_zip:
            with tarfile.open(mode=self.TAR_MODE, fileobj=f_zip, format=self.TAR_FORMAT) as f_tar:

                def _tar_filter(tarinfo: tarfile.TarInfo):
                    if len(tarinfo.name) > self.ENTRY_NAME_MAX_LENGTH:
                        raise ValueError("Resource name too long")
                    tarinfo.gid = tarinfo.uid = 0
                    tarinfo.mtime = 0
                    tarinfo.uname = tarinfo.gname = "furippa"
                    return tarinfo

                f_tar.add(
                    pack_compiled,
                    arcname="",
                    filter=_tar_filter,
                )

        shutil.rmtree(pack_compiled)

    def parse(self, packpath: str) -> Pack:
        id = os.path.basename(packpath)

        self._rebuild(packpath)

        meta_path = os.path.join(packpath, "meta.json")
        with open(meta_path, "r") as f:
            meta: dict = json.load(f)

        # TODO: Compute pack info like passport icons, count of anims...
        pack = Pack(
            id=id,
            name=meta.get("name", id.title()),
            author=meta.get("author", "N/A"),
            source_url=meta.get("source_url"),
            description=meta.get("description"),
        )

        files_path = os.path.join(packpath, "file")
        for cur in sorted(os.listdir(files_path)):
            # skip .DS_store files
            if cur.startswith("."):
                continue
            if not cur.endswith((".zip", ".tar.gz")):
                continue
            file_path = os.path.join(files_path, cur)
            pack.add_file(
                PackFile(
                    url=os.path.join(
                        settings.base_url,
                        os.path.relpath(file_path, settings.files_dir),
                    ),
                    type="pack_" + cur.rsplit(".", 1)[-1].replace("gz", "targz"),
                    sha256=self.getSHA256(file_path),
                )
            )

        previews_path = os.path.join(packpath, "preview")
        if os.path.isdir(previews_path):
            for cur in sorted(os.listdir(previews_path)):
                # skip .DS_store files
                if cur.startswith("."):
                    continue
                if not cur.endswith((".png", ".jpg", ".gif", ".mp4", ".webm")):
                    continue
                preview_path = os.path.join(previews_path, cur)
                pack.add_preview_url(
                    os.path.join(
                        settings.base_url,
                        os.path.relpath(preview_path, settings.files_dir),
                    )
                )

        return pack
