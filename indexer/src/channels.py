from .models import Channel


development_channel = Channel(
    id="development",
    title="Development Channel",
    description="Latest builds, might sometimes be unstable",
)
release_channel = Channel(
    id="release",
    title="Stable Release Channel",
    description="Less frequent, more stable releases",
)
pr_channel = Channel(
    id="pr{pr}:{branch}",
    title="Branch '{branch}' (PR #{pr})",
    description="",
)
