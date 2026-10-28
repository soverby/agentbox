"""Image pruning (PLAN §2.10): the managed-tag filter, the keep rules, removal
without -f, `df` sizes and freed space, the abort rules, `prune.json`, and the
output lines. A fake Docker answers every call; nothing touches a real daemon."""

import json
import stat

import pytest
from agentbox import docker, images, prune, schedule, updatelock
from conftest import ROOT
from fakedocker import GB, FakeDocker, sha

CUR_HASH = images.agent_hash(ROOT)
AT = "2026-10-28T05:00:00+01:00"
PKGS = [("media", ["ffmpeg"]), ("docs", ["pandoc"])]


@pytest.fixture
def d(tmp_path, monkeypatch):
    """A fake daemon wired to docker.run, a fixed clock, and a private state root."""
    monkeypatch.setenv("AGENTBOX_STATE_HOME", str(tmp_path / "state"))
    fake = FakeDocker()
    monkeypatch.setattr(docker, "run", fake.run)
    monkeypatch.setattr(schedule, "now_iso", lambda: AT)
    return fake


def hexn(n: int) -> str:
    return f"{n:012x}"


def agent(d, n, day, *, current=False, latest=False, base=True, size=GB):
    """An agent image `sha(n)`: its hash tag (the real current hash when `current`)."""
    tags = [f"{images.AGENT_REPO}:{CUR_HASH if current else hexn(n)}"]
    if base:
        tags.append(f"{images.AGENT_REPO}:base-{sha(n)[7:19]}")
    if latest:
        tags.append(images.AGENT_LATEST)
    return d.image(n, tags, day, size)


def sidecar(d, name, n, day, *, current=False):
    tag = images.sidecar_tag(ROOT, name) if current else f"agentbox/{name}:{hexn(n)}"
    return d.image(n, [tag], day)


def derived(d, base_id, packages, n, day):
    return d.image(n, [images.pkgs_tag(base_id, packages)], day)


def rm_calls(d):
    return [c for c in d.calls if c[:3] == ["docker", "image", "rm"]]


def run(d, profs=PKGS, **kw):
    return prune.run(ROOT, profs, **kw)


# ---------------------------------------------------------------- managed tags
@pytest.mark.parametrize(
    "ref,kind",
    [
        ("agentbox/agent:0123456789ab", "agent"),
        ("agentbox/agent:base-0123456789ab", "agent"),
        ("agentbox/agent-pkgs:0123456789ab", "pkgs"),
        ("agentbox/egress:0123456789ab", "egress"),
        ("agentbox/ollama-gate:0123456789ab", "ollama-gate"),
        ("agentbox/mcp-gateway:0123456789ab", "mcp-gateway"),
        ("agentbox/router:0123456789ab", "router"),
        ("agentbox/agent:latest", None),
        ("agentbox/agent:p2test", None),
        ("agentbox/agent:0123456789a", None),  # 11 hex
        ("agentbox/agent:0123456789abc", None),  # 13 hex
        ("agentbox/agent:0123456789AB", None),  # upper case
        ("agentbox/agent:base-0123456789a", None),
        ("agentbox/agent-pkgs:base-0123456789ab", None),
        ("agentbox/egress:base-0123456789ab", None),
        ("agentbox/other:0123456789ab", None),  # not in SIDECARS
        ("other/agent:0123456789ab", None),
        ("registry:5000/agentbox/agent:0123456789ab", None),
        ("agentbox/agent:<none>", None),
        ("<none>:<none>", None),
        ("finance-api:latest", None),
    ],
)
def test_managed_tag_filter(ref, kind):
    assert prune.kind_of(ref) == kind


def test_every_sidecar_is_managed():
    for name in images.SIDECARS:
        assert prune.kind_of(f"agentbox/{name}:{hexn(1)}") == name


# ---------------------------------------------------------------- keep rules
def test_nothing_to_remove_when_only_current_images_exist(d):
    agent(d, 1, 5, current=True, latest=True)
    rec = run(d)
    assert rec["removed"] == [] and rec["images"] == [] and rec["error"] is None
    assert rm_calls(d) == []


def test_keeps_current_previous_and_removes_the_rest(d):
    cur = agent(d, 1, 10, current=True, latest=True)
    prev = agent(d, 2, 9)
    agent(d, 3, 8)
    agent(d, 4, 7)
    rec = run(d)
    assert set(d.ids()) == {cur, prev}
    assert sorted(rec["images"]) == [sha(3), sha(4)]
    assert sorted(rec["removed"]) == sorted(
        [f"agentbox/agent:{hexn(3)}", f"agentbox/agent:base-{sha(3)[7:19]}",
         f"agentbox/agent:{hexn(4)}", f"agentbox/agent:base-{sha(4)[7:19]}"]
    )  # fmt: skip


def test_current_is_the_id_of_latest_and_of_the_hash_tag(d):
    """latest and the hash tag may name different ids (a build that did not move latest):
    both are current, and the previous one is the newest of the rest."""
    hash_id = d.image(1, [f"{images.AGENT_REPO}:{CUR_HASH}"], 10)
    latest_id = d.image(2, [images.AGENT_LATEST, f"{images.AGENT_REPO}:{hexn(2)}"], 9)
    prev = agent(d, 3, 8)
    agent(d, 4, 7)
    rec = run(d)
    assert set(d.ids()) == {hash_id, latest_id, prev}
    assert rec["images"] == [sha(4)]


def test_previous_is_the_newest_by_created_not_by_list_order(d):
    agent(d, 1, 10, current=True, latest=True)
    agent(d, 9, 3)  # listed first, oldest
    newer = agent(d, 5, 8)  # the previous
    agent(d, 7, 6)
    rec = run(d)
    assert newer in d.ids() and sorted(rec["images"]) == [sha(7), sha(9)]
    inspect = [c for c in d.calls if c[:3] == ["docker", "image", "inspect"]]
    assert inspect and "{{.Created}}" in inspect[0][4]  # the time comes from Created


def test_created_with_nanoseconds_and_offsets_is_compared_as_time(d):
    agent(d, 1, 10, current=True, latest=True)
    older, newer = agent(d, 2, 5, base=False), agent(d, 3, 5, base=False)
    d.created[older] = "2026-10-05T12:00:00.123456789+02:00"  # 10:00 UTC
    d.created[newer] = "2026-10-05T11:00:00.000000001Z"  # later in UTC
    rec = run(d)
    assert rec["images"] == [older] and newer in d.ids()


def test_derived_images_of_current_and_previous_are_kept(d):
    cur = agent(d, 1, 10, current=True, latest=True)
    prev = agent(d, 2, 9)
    old = agent(d, 3, 8)
    kept = [derived(d, cur, ["ffmpeg"], 11, 10), derived(d, prev, ["ffmpeg"], 12, 9),
            derived(d, cur, ["pandoc"], 13, 10)]  # fmt: skip
    gone = derived(d, old, ["ffmpeg"], 14, 8)
    stray = d.image(15, [f"{images.PKGS_REPO}:{hexn(15)}"], 7)  # no profile derives it
    other = derived(d, cur, ["unrelated"], 16, 10)  # a package set no profile has
    rec = run(d)
    assert set(kept) <= set(d.ids())
    assert sorted(rec["images"]) == sorted([old, gone, stray, other])


def test_derived_of_a_profile_without_packages_is_not_a_keep_rule(d):
    cur = agent(d, 1, 10, current=True, latest=True)
    der = derived(d, cur, ["ffmpeg"], 11, 10)
    rec = run(d, profs=[])
    assert rec["images"] == [der]


def test_derived_removed_before_its_base(d):
    cur = agent(d, 1, 10, current=True, latest=True)
    agent(d, 2, 9)
    old = agent(d, 3, 8)
    der = derived(d, old, ["ffmpeg"], 14, 8)
    run(d)
    order = [c[3] for c in rm_calls(d)]
    assert order.index(images.pkgs_tag(old, ["ffmpeg"])) < order.index(f"agentbox/agent:{hexn(3)}")
    assert cur in d.ids() and der not in d.ids()


def test_sidecars_keep_current_and_the_newest_non_current(d):
    agent(d, 1, 10, current=True, latest=True)
    cur = sidecar(d, "egress", 21, 10, current=True)
    prev = sidecar(d, "egress", 22, 9)
    sidecar(d, "egress", 23, 8)
    only = sidecar(d, "router", 31, 3)  # no current router image: its newest is kept
    sidecar(d, "router", 32, 2)
    other_cur = sidecar(d, "mcp-gateway", 41, 10, current=True)
    rec = run(d)
    assert {cur, prev, only, other_cur} <= set(d.ids())
    assert sorted(rec["images"]) == sorted([sha(23), sha(32)])


def test_sidecar_and_agent_generations_are_independent(d):
    agent(d, 1, 10, current=True, latest=True)
    agent(d, 2, 9)
    egress_old = sidecar(d, "egress", 21, 1)  # old, but the only non-current egress: kept
    assert run(d)["images"] == []
    assert egress_old in d.ids()


def test_any_container_keeps_its_image_running_or_stopped(d):
    agent(d, 1, 10, current=True, latest=True)
    agent(d, 2, 9)
    used = agent(d, 3, 8)
    used_der = derived(d, used, ["ffmpeg"], 14, 8)
    free = agent(d, 4, 7)
    d.containers = [used, used_der]
    rec = run(d)
    assert {used, used_der} <= set(d.ids()) and rec["images"] == [free]
    assert ["docker", "ps", "-a", "-q", "--no-trunc"] in d.calls  # -a: stopped ones too


def test_other_repositories_and_untracked_tags_are_never_removed(d):
    agent(d, 1, 10, current=True, latest=True)
    agent(d, 2, 9)
    other = d.image(50, ["finance-api:latest", "agentbox/agent:p2test"], 1)
    d.tags["<none>:<none>"] = sha(51)
    d.created[sha(51)], d.sizes[sha(51)] = d.created[other], GB
    rec = run(d)
    assert rec["images"] == [] and rec["removed"] == []
    assert rm_calls(d) == [] and "finance-api:latest" in d.tags


def test_without_a_current_agent_image_nothing_is_removed(d):
    agent(d, 2, 9)
    agent(d, 3, 8)
    rec = run(d)
    assert "no current agent image" in rec["error"]
    assert rm_calls(d) == [] and d.calls[-1][:3] != ["docker", "builder", "prune"]


# ---------------------------------------------------------------- removal
def test_removal_is_one_call_per_image_with_all_its_tags_and_never_forces(d):
    agent(d, 1, 10, current=True, latest=True)
    agent(d, 2, 9)
    agent(d, 3, 8)
    agent(d, 4, 7)
    run(d)
    calls = rm_calls(d)
    assert len(calls) == 2
    assert calls[0] == ["docker", "image", "rm", f"agentbox/agent:{hexn(3)}",
                        f"agentbox/agent:base-{sha(3)[7:19]}"]  # fmt: skip
    assert all("-f" not in c and "--force" not in c for c in calls)  # builder prune has --force


def test_removed_are_the_untagged_lines_and_images_the_deleted_ones(d):
    agent(d, 1, 10, current=True, latest=True)
    agent(d, 2, 9)
    agent(d, 3, 8)
    rec = run(d)
    assert rec["removed"] == [f"agentbox/agent:{hexn(3)}", f"agentbox/agent:base-{sha(3)[7:19]}"]
    assert rec["images"] == [sha(3)] and rec["kept_busy"] == []


def test_a_non_managed_tag_keeps_the_image_and_is_kept_busy(d):
    agent(d, 1, 10, current=True, latest=True)
    agent(d, 2, 9)
    held = agent(d, 3, 8)
    d.tags["myproject/base:1"] = held  # someone else's tag on the same image
    rec = run(d)
    assert rec["kept_busy"] == [held] and rec["images"] == [] and rec["error"] is None
    assert held in d.ids() and "myproject/base:1" in d.tags
    assert len(rec["removed"]) == 2  # the managed tags are gone


def test_a_conflict_is_kept_busy_not_an_error(d):
    agent(d, 1, 10, current=True, latest=True)
    agent(d, 2, 9)
    race = agent(d, 3, 8)
    d.busy_ids.add(race)  # a container appeared after the list
    free = agent(d, 4, 7)
    rec = run(d)
    assert rec["kept_busy"] == [race] and rec["images"] == [free] and rec["error"] is None


def test_another_failure_is_an_error_and_the_prune_goes_on(d, monkeypatch):
    agent(d, 1, 10, current=True, latest=True)
    agent(d, 2, 9)
    agent(d, 3, 8)
    agent(d, 4, 7)
    real = d.run

    def run_(args, **kw):
        if args[:3] == ["docker", "image", "rm"] and f"agentbox/agent:{hexn(3)}" in args:
            d.calls.append(list(args))
            return d.result(args, 1, "", "Error response from daemon: disk on fire\n")
        return real(args, **kw)

    monkeypatch.setattr(docker, "run", run_)
    rec = run(d)
    assert rec["images"] == [sha(4)] and rec["kept_busy"] == []
    assert "disk on fire" in rec["error"] and sha(3)[:19] in rec["error"]


def test_a_docker_exception_during_removal_is_an_error(d, monkeypatch):
    agent(d, 1, 10, current=True, latest=True)
    agent(d, 2, 9)
    agent(d, 3, 8)
    real = d.run

    def run_(args, **kw):
        if args[:3] == ["docker", "image", "rm"]:
            raise docker.DockerError("docker: command not found")
        return real(args, **kw)

    monkeypatch.setattr(docker, "run", run_)
    rec = run(d)
    assert rec["images"] == [] and "command not found" in rec["error"]


# ---------------------------------------------------------------- abort rules
@pytest.mark.parametrize("key", ["ps -a", "image ls", "container inspect", "image inspect"])
def test_a_failed_listing_removes_nothing(d, key):
    agent(d, 1, 10, current=True, latest=True)
    agent(d, 2, 9)
    agent(d, 3, 8)
    agent(d, 4, 7)
    d.containers = [sha(4)]  # so that `container inspect` is asked
    before = dict(d.tags)
    d.fail[key] = (1, "Cannot connect to the Docker daemon")
    rec = run(d)
    assert rec["error"] and "Cannot connect" in rec["error"] and key.split()[0] in rec["error"]
    assert rec["removed"] == [] and rec["images"] == [] and rec["freed_bytes"] is None
    assert rm_calls(d) == []
    assert not any(c[:3] == ["docker", "builder", "prune"] for c in d.calls)
    assert d.tags == before  # every tag is still there


def test_a_docker_that_is_not_installed_removes_nothing(d, monkeypatch):
    def gone(args, **kw):
        raise docker.DockerError("docker: command not found")

    monkeypatch.setattr(docker, "run", gone)
    rec = run(d)
    assert "command not found" in rec["error"] and rec["removed"] == []


# ---------------------------------------------------------------- build cache and sizes
def test_build_cache_prune_runs_after_the_image_removal_with_the_24h_filter(d):
    agent(d, 1, 10, current=True, latest=True)
    agent(d, 2, 9)
    agent(d, 3, 8)
    run(d)
    kinds = [c[1:3] for c in d.calls if c[1:3] in (["image", "rm"], ["builder", "prune"])]
    assert kinds == [["image", "rm"], ["builder", "prune"]]
    assert ["docker", "builder", "prune", "--force", "--filter", "until=24h"] in d.calls


def test_build_cache_prune_runs_when_no_image_is_removed(d):
    agent(d, 1, 10, current=True, latest=True)
    run(d)
    assert ["docker", "builder", "prune", "--force", "--filter", "until=24h"] in d.calls


def test_a_failed_builder_prune_is_an_error_after_the_images_went(d):
    agent(d, 1, 10, current=True, latest=True)
    agent(d, 2, 9)
    agent(d, 3, 8)
    d.fail["builder prune"] = (1, "ERROR: buildkit is down")
    rec = run(d)
    assert rec["images"] == [sha(3)] and "buildkit is down" in rec["error"]


@pytest.mark.parametrize(
    "text,n",
    [
        ("0B", 0),
        ("512B", 512),
        ("134.5kB", 134_500),
        ("134.5KB", 134_500),
        ("7.565MB", 7_565_000),
        ("23.31GB", 23_310_000_000),
        ("1.5TB", 1_500_000_000_000),
        ("7.353GB (31%)", 7_353_000_000),  # first token only
        ("  2GB", 2 * GB),
    ],
)
def test_parse_size_is_decimal_and_reads_the_first_token(text, n):
    assert prune.parse_size(text) == n


@pytest.mark.parametrize("text", ["", "GB", "12", "1.5GiB", "x MB", "-3GB"])
def test_parse_size_refuses_what_it_cannot_read(text):
    with pytest.raises(ValueError):
        prune.parse_size(text)


def test_freed_is_the_drop_in_images_size_plus_cache_reclaimable(d):
    agent(d, 1, 10, current=True, latest=True, size=2 * GB)
    agent(d, 2, 9, size=2 * GB)
    agent(d, 3, 8, size=3 * GB)
    agent(d, 4, 7, size=1 * GB)
    d.cache, d.cache_after_prune = 500_000_000, 100_000_000
    rec = run(d)
    # images 8 GB -> 4 GB; cache reclaimable 0.5 GB -> 0.1 GB
    assert rec["freed_bytes"] == 4 * GB + 400_000_000
    assert rec["after"] == {"images": 4 * GB, "build_cache": 100_000_000}


def test_build_cache_size_is_not_used_only_reclaimable(d):
    agent(d, 1, 10, current=True, latest=True)
    run(d)
    dfs = [c for c in d.calls if c[1:3] == ["system", "df"]]
    assert dfs and dfs[0] == ["docker", "system", "df", "--format", "{{json .}}"]
    assert run(d)["freed_bytes"] == 0  # the 15.36GB cache `Size` of the fake is ignored


def test_freed_is_clamped_at_zero(d, monkeypatch):
    agent(d, 1, 10, current=True, latest=True)
    agent(d, 2, 9)
    agent(d, 3, 8, size=GB)
    real = d.run
    n = []

    def grow(args, **kw):  # another project builds during the prune: df grows
        if args[1:3] == ["system", "df"]:
            n.append(1)
            d.cache = 0 if len(n) == 1 else 9 * GB
        return real(args, **kw)

    monkeypatch.setattr(docker, "run", grow)
    rec = run(d)
    assert rec["freed_bytes"] == 0 and rec["images"] == [sha(3)]


def test_a_failed_df_gives_freed_null_and_the_prune_still_runs(d):
    agent(d, 1, 10, current=True, latest=True)
    agent(d, 2, 9)
    agent(d, 3, 8)
    d.fail["df"] = (1, "df failed")
    rec = run(d)
    assert rec["freed_bytes"] is None and rec["after"] is None and rec["error"] is None
    assert rec["images"] == [sha(3)]
    assert ["docker", "builder", "prune", "--force", "--filter", "until=24h"] in d.calls


@pytest.mark.parametrize("text", ["not json\n", "{}\n", '{"Type": "Images", "Size": "1GB"}\n',
                                  '{"Type":"Images","Size":"?","Reclaimable":"0B"}\n'])  # fmt: skip
def test_unreadable_df_output_is_unknown_not_a_crash(d, text):
    agent(d, 1, 10, current=True, latest=True)
    d.df_text = text
    rec = run(d)
    assert rec["freed_bytes"] is None and rec["after"] is None and rec["error"] is None


# ---------------------------------------------------------------- dry run
def test_dry_run_lists_the_tags_and_removes_nothing(d):
    agent(d, 1, 10, current=True, latest=True)
    agent(d, 2, 9)
    agent(d, 3, 8)
    before = dict(d.tags)
    rec = run(d, dry_run=True)
    assert rec["removed"] == [f"agentbox/agent:{hexn(3)}", f"agentbox/agent:base-{sha(3)[7:19]}"]
    assert rec["images"] == [sha(3)] and rec["error"] is None and rec["dry_run"] is True
    assert d.tags == before
    assert rm_calls(d) == [] and not any(c[1:3] == ["builder", "prune"] for c in d.calls)


def test_dry_run_with_a_failed_ps_is_an_error(d):
    agent(d, 1, 10, current=True, latest=True)
    d.fail["ps -a"] = (1, "down")
    assert "docker ps -a failed" in run(d, dry_run=True)["error"]


# ---------------------------------------------------------------- prune.json and text
def test_write_makes_prune_json_with_mode_0600(d):
    agent(d, 1, 10, current=True, latest=True)
    agent(d, 2, 9)
    agent(d, 3, 8)
    rec = run(d)
    prune.write(rec)
    f = updatelock.update_dir() / "prune.json"
    assert stat.S_IMODE(f.stat().st_mode) == 0o600
    assert json.loads(f.read_text()) == rec
    assert set(rec) == {"end", "removed", "images", "kept_busy", "freed_bytes", "after", "error"}
    assert rec["end"] == AT


def test_dry_run_flag_is_not_written(d):
    agent(d, 1, 10, current=True, latest=True)
    agent(d, 2, 9)
    agent(d, 3, 8)
    prune.write(run(d, dry_run=True))
    assert "dry_run" not in json.loads((updatelock.update_dir() / "prune.json").read_text())


@pytest.mark.parametrize(
    "n,text",
    [(0, "0.0"), (49_999_999, "0.0"), (50_000_000, "0.1"), (100_000_000, "0.1"),
     (4_250_000_000, "4.3"), (23_310_000_000, "23.3")],
)  # fmt: skip
def test_gb_has_one_decimal_in_decimal_units(n, text):
    assert prune.gb(n) == text


def test_post_suffix_starts_at_a_tenth_of_a_gigabyte():
    assert prune.post_suffix(None) == "" and prune.post_suffix(0) == ""
    assert prune.post_suffix(99_999_999) == ""
    assert prune.post_suffix(100_000_000) == "; freed 0.1 GB"
    assert prune.post_suffix(4_250_000_000) == "; freed 4.3 GB"


def rec_of(**kw):
    rec = prune.new_record()
    rec.update(end=AT, **kw)
    return rec


def test_output_line():
    rec = rec_of(images=["a", "b", "c"], freed_bytes=4_250_000_000,
                 after={"images": 12_300_000_000, "build_cache": 500_000_000})  # fmt: skip
    assert prune.lines(rec) == [
        "pruned 3 images, freed 4.3 GB (images 12.3 GB, build cache 0.5 GB now)"
    ]
    assert prune.lines(rec_of(images=["a"], freed_bytes=0)) == ["pruned 1 image, freed 0.0 GB"]
    assert prune.lines(rec_of()) == ["pruned 0 images, freed unknown"]


def test_output_for_an_error_is_one_line_and_a_partial_prune_shows_both():
    assert prune.lines(rec_of(error="docker ps -a failed (1): down")) == [
        "prune failed: docker ps -a failed (1): down"
    ]
    lines = prune.lines(rec_of(images=["a"], freed_bytes=GB, error="builder prune failed"))
    assert lines[0].startswith("pruned 1 image, freed 1.0 GB") and lines[1].startswith(
        "prune failed"
    )


def test_output_text_is_cleaned_for_the_terminal():
    (line,) = prune.lines(rec_of(error="bad \x1b[31mred\x1b[0m"))
    assert "\x1b" not in line


def test_dry_run_output_lists_every_tag():
    rec = rec_of(
        images=["a"], removed=["agentbox/agent:aaaaaaaaaaaa", "agentbox/agent:base-aaaaaaaaaaaa"]
    )
    rec["dry_run"] = True
    assert prune.lines(rec) == [
        "would remove 1 image (2 tags):",
        "  agentbox/agent:aaaaaaaaaaaa",
        "  agentbox/agent:base-aaaaaaaaaaaa",
    ]


def test_fleet_line():
    ok = rec_of(images=["a", "b", "c"], freed_bytes=4_250_000_000,
                after={"images": 12_300_000_000, "build_cache": 500_000_000})  # fmt: skip
    assert prune.fleet_line(ok, "05:00") == (
        "Docker disk: pruned 3 images, freed 4.3 GB at 05:00; images 12.3 GB, build cache 0.5 GB"
    )
    assert prune.fleet_line(rec_of(error="docker ps -a failed (1): down"), "05:00") == (
        "Docker disk: prune failed at 05:00: docker ps -a failed (1): down"
    )
    assert prune.fleet_line(rec_of(images=["a"]), "05:00") == (
        "Docker disk: pruned 1 image, freed unknown at 05:00"
    )
