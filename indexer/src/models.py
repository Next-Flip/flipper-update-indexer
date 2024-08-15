import re
import hashlib
import logging
from pydantic import BaseModel
from github import Github, Repository
from typing import List, ClassVar


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

    def get_unstable_branch_names(self) -> List[str]:
        return [
            branch
            for branch in self.__branches
            if branch
            not in (
                "dev",
                "release",
            )
        ]

    """
        We need all stuff above (except login) for the delete_unlinked_directories function in repository.py
    """

    def is_branch_exist(self, branch: str) -> bool:
        return branch in self.__branches

    def is_release_exist(self, release: str) -> bool:
        return release in self.__releases

    def is_tag_exist(self, tag: str) -> bool:
        return tag in self.__tags

    def get_dev_version(self, branch: str) -> Version:
        try:
            commits = self.__repo.get_commits(branch)
            if commits.totalCount == 0:
                exception_msg = f"No commits found in {branch} branch!"
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
