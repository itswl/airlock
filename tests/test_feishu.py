"""The Feishu adapter: cards out of the outlet, one thread per work item, and replies back only from you."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from airlock.crypto import sign, verify
from airlock.extras.feishu import render
from airlock.extras.feishu.app import Cards, create_app
from airlock.extras.feishu.config import load_feishu
from airlock.extras.feishu.inbound import handle, text_of
from airlock.extras.feishu.lark import Lark, Webhook
from airlock.extras.settings import SettingsError

SUB, NOTICE, ADAPTER, INTAKE = "s" * 32, "n" * 32, "a" * 32, "i" * 32
ME, OTHER = "ou_me", "ou_someone_else"


class FakeLark:
    """The open platform's token and message endpoints, recording what was sent."""

    def __init__(self) -> None:
        self.sent: list[dict[str, Any]] = []
        self.next = 0

    def __call__(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/tenant_access_token/internal"):
            return httpx.Response(200, json={"code": 0, "tenant_access_token": "tok", "expire": 7200})
        assert request.headers["authorization"] == "Bearer tok"
        self.next += 1
        body = json.loads(request.content)
        kind = "reply" if path.endswith("/reply") else "send"
        self.sent.append({"kind": kind, "path": path, "params": dict(request.url.params), **body})
        return httpx.Response(200, json={"code": 0, "data": {"message_id": f"om_{self.next}"}})


def config_for(tmp_path: Path, **overrides: Any) -> Any:
    data = {
        "name": "feishu",
        "brand": "lark",
        "app_id_env": "T_APP",
        "app_secret_env": "T_APP_SECRET",
        "plans_chat": "oc_plans",
        "notices_chat": "oc_notices",
        "subscription_secret_env": "T_SUB",
        "notice_secret_env": "T_NOTICE",
        "people_env": "T_PEOPLE",
        "airlock": {
            "adapter_url": "http://control/v1/adapters/feishu",
            "adapter_secret_env": "T_ADAPTER",
            "intake_url": "http://control/v1/intake/feishu",
            "intake_secret_env": "T_INTAKE",
            "console_url": "http://console.invalid",
        },
        "state": str(tmp_path / "feishu.db"),
        **overrides,
    }
    env = {
        "T_APP": "cli_x",
        "T_APP_SECRET": "x",
        "T_SUB": SUB,
        "T_NOTICE": NOTICE,
        "T_PEOPLE": ME,
        "T_ADAPTER": ADAPTER,
        "T_INTAKE": INTAKE,
    }
    return load_feishu(data, env)


def adapter(tmp_path: Path) -> tuple[Any, Cards, FakeLark, TestClient]:
    config, fake = config_for(tmp_path), FakeLark()
    cards = Cards(config, Lark("cli_x", "x", brand="lark", transport=httpx.MockTransport(fake)))
    return config, cards, fake, TestClient(create_app(config, cards))


def outlet(client: TestClient, delivery: int, event: str, payload: dict[str, Any]) -> httpx.Response:
    body = json.dumps({"id": delivery, "event": event, "at": 1.0, "payload": payload}).encode()
    return client.post("/airlock", content=body, headers={**sign(SUB, body), "Content-Type": "application/json"})


PLAN = {
    "work_id": "w1",
    "title": "Checkout is slow",
    "link": "http://console.invalid/work/w1",
    "version": 1,
    "plan_hash": "h",
    "summary": "Restart <at id=all></at> the api",
    "risk": "low",
    "changed": False,
}


def test_a_work_item_s_cards_go_into_one_thread_and_a_redelivery_is_sent_once(tmp_path: Path) -> None:
    _, cards, fake, client = adapter(tmp_path)
    assert outlet(client, 1, "plan.ready", PLAN).json()["message_id"] == "om_1"
    assert outlet(client, 1, "plan.ready", PLAN).json()["status"] == "already sent"
    finished = {
        **PLAN,
        "status": "done",
        "groups": [
            {
                "worker": "code",
                "status": "done",
                "workspace": {"repo": "demo", "files_changed": 2, "insertions": 7, "deletions": 1},
            }
        ],
    }
    assert outlet(client, 2, "run.finished", finished).status_code == 200
    assert outlet(client, 3, "work.created", PLAN).json()["status"] == "no card for this event"
    assert [(s["kind"], s["params"].get("receive_id_type")) for s in fake.sent] == [
        ("send", "chat_id"),
        ("reply", None),
    ]
    assert fake.sent[0]["receive_id"] == "oc_plans" and fake.sent[1]["path"].endswith("/om_1/reply")
    assert fake.sent[1]["reply_in_thread"] is True
    first = json.loads(fake.sent[0]["content"])
    markdown = [e["text"]["content"] for e in first["elements"] if e.get("tag") == "div"]
    assert markdown[0] == "**Restart \\<at id=all>\\</at> the api**"  # neutralised: no one is paged
    buttons = [a for e in first["elements"] if e.get("tag") == "action" for a in e["actions"]]
    assert [(b["text"]["content"], b["url"]) for b in buttons] == [("看方案并批准", "http://console.invalid/work/w1")]
    done = json.dumps(json.loads(fake.sent[1]["content"]), ensure_ascii=False)
    assert "改了 demo 的 2 个文件，+7 −1" in done
    assert cards.card("om_2")["work_id"] == "w1"


def test_a_card_never_carries_an_approve_button(tmp_path: Path) -> None:
    card = render.for_event("plan.ready", PLAN)
    buttons = [a for e in card["elements"] if e.get("tag") == "action" for a in e["actions"]]
    assert buttons and all("url" in b and "value" not in b for b in buttons)  # links to the console only


def test_unsigned_or_wrongly_signed_is_refused(tmp_path: Path) -> None:
    _, _, fake, client = adapter(tmp_path)
    body = json.dumps({"id": 1, "event": "plan.ready", "payload": PLAN}).encode()
    assert client.post("/airlock", content=body).status_code == 401
    assert client.post("/airlock", content=body, headers=sign("w" * 32, body)).status_code == 401
    assert (
        client.post("/notice", content=body, headers=sign(SUB, body)).status_code == 401
    )  # the outlet's secret is not the notice door's
    assert fake.sent == []


def test_a_note_is_carded_in_the_notices_chat_and_a_task_links_to_its_work_item(tmp_path: Path) -> None:
    _, cards, fake, client = adapter(tmp_path)
    task = {
        "title": "Rotate the cert",
        "detail": "Ann asked",
        "level": "high",
        "kind": "task",
        "origin": "chat / ops",
        "work_id": "w9",
    }
    body = json.dumps(task).encode()
    answer = client.post("/notice", content=body, headers={**sign(NOTICE, body), "Content-Type": "application/json"})
    assert answer.status_code == 200 and fake.sent[0]["receive_id"] == "oc_notices"
    assert "http://console.invalid/work/w9" in fake.sent[0]["content"]
    assert cards.card(answer.json()["message_id"])["kind"] == "notice"


def message_event(
    root: str = "",
    sender: str = ME,
    text: str = "@_user_1 先 drain 再重启",
    chat: str = "oc_plans",
    sender_type: str = "user",
    message_id: str = "om_in_1",
) -> dict[str, Any]:
    return {
        "sender": {"sender_id": {"open_id": sender}, "sender_type": sender_type},
        "message": {
            "message_id": message_id,
            "root_id": root,
            "parent_id": root,
            "chat_id": chat,
            "message_type": "text",
            "content": json.dumps({"text": text}),
        },
    }


class Doors:
    def __init__(self) -> None:
        self.posted: list[tuple[str, dict[str, Any]]] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        secret = ADAPTER if "/adapters/" in request.url.path else INTAKE
        verify(secret, request.content, request.headers)
        self.posted.append((request.url.path, json.loads(request.content)))
        return httpx.Response(200 if "/adapters/" in request.url.path else 202, json={"work_id": "w-new"})


def test_a_reply_under_a_work_card_becomes_your_message_on_that_item(tmp_path: Path) -> None:
    config, cards, _, client = adapter(tmp_path)
    outlet(client, 1, "plan.ready", PLAN)
    doors = Doors()
    http = httpx.Client(transport=httpx.MockTransport(doors))
    assert handle(config, cards, message_event(root="om_1"), client=http) == "message on w1: 200"
    assert doors.posted == [
        ("/v1/adapters/feishu/message", {"work_id": "w1", "text": "先 drain 再重启", "platform_user": ME})
    ]
    assert handle(config, cards, message_event(root="om_1"), client=http) == "ignored: already handled"
    assert handle(config, cards, message_event(root="om_1", sender=OTHER, message_id="m2"), client=http).startswith(
        "ignored: this person"
    )
    assert (
        handle(config, cards, message_event(root="om_1", sender_type="app", message_id="m3"), client=http)
        == "ignored: not a person"
    )
    assert handle(config, cards, message_event(root="om_1", chat="oc_else", message_id="m4"), client=http).startswith(
        "ignored: not one"
    )
    assert handle(config, cards, message_event(root="om_404", message_id="m5"), client=http).startswith(
        "ignored: a reply under a card"
    )
    assert len(doors.posted) == 1


def test_a_reply_under_a_note_or_a_new_topic_opens_a_work_item(tmp_path: Path) -> None:
    config, cards, _, client = adapter(tmp_path)
    note = {
        "title": "Cert expires Friday",
        "detail": "Bob in ops",
        "level": "low",
        "kind": "note",
        "origin": "chat / ops",
    }
    body = json.dumps(note).encode()
    root = client.post("/notice", content=body, headers=sign(NOTICE, body)).json()["message_id"]
    doors = Doors()
    http = httpx.Client(transport=httpx.MockTransport(doors))
    assert (
        handle(config, cards, message_event(root=root, chat="oc_notices", text="@_user_1 查一下怎么续"), client=http)
        == "new work item: 202"
    )
    path, signal = doors.posted[0]
    assert (
        path == "/v1/intake/feishu" and signal["title"] == "查一下怎么续" and "Cert expires Friday" in signal["detail"]
    )
    assert signal["origin"] == "feishu / reply"
    assert (
        handle(config, cards, message_event(message_id="m-topic", text="@_user_1 看看 CDN"), client=http)
        == "new work item: 202"
    )
    assert doors.posted[1][1]["origin"] == "feishu / topic"


def test_rich_text_and_mentions_are_read_as_words() -> None:
    post = {
        "message_type": "post",
        "content": json.dumps({"content": [[{"tag": "at", "user_id": "x"}, {"tag": "text", "text": "先看日志"}]]}),
    }
    assert text_of(post) == "先看日志"
    assert (
        text_of({"message_type": "text", "content": json.dumps({"text": "@_user_1  hi @_user_2 there"})}) == "hi there"
    )


def test_airlock_takes_the_adapter_s_message_only_from_a_mapped_person(
    tmp_path: Path, config_dict: dict[str, Any], env: dict[str, str]
) -> None:
    from airlock.config import load_control
    from airlock.control.service import ControlPlane

    plane = ControlPlane(
        load_control(
            {**config_dict, "adapters": [{"name": "feishu", "secret_env": "T_ADAPTER", "identities": [ME]}]},
            {**env, "T_ADAPTER": ADAPTER},
        )
    )
    config, cards, _, client = adapter(tmp_path)
    work_id = plane.manual_signal("Checkout is slow", "p99 4s").body["work_id"]
    outlet(client, 1, "plan.ready", {**PLAN, "work_id": work_id})

    def control(request: httpx.Request) -> httpx.Response:
        verify(ADAPTER, request.content, request.headers)
        outcome = plane.adapter_message("feishu", json.loads(request.content))
        return httpx.Response(outcome.status, json=outcome.body)

    http = httpx.Client(transport=httpx.MockTransport(control))
    assert handle(config, cards, message_event(root="om_1", text="@_user_1 先 drain"), client=http).startswith(
        f"message on {work_id}"
    )
    texts = [m["text"] for m in plane.db.all("SELECT text FROM messages WHERE work_id = ?", [work_id])]
    assert "先 drain" in texts


def test_a_custom_bot_signs_and_cannot_thread() -> None:
    seen: list[dict[str, Any]] = []

    def bot(request: httpx.Request) -> httpx.Response:
        seen.append(json.loads(request.content))
        return httpx.Response(200, json={"code": 0})

    hook = Webhook("https://bot.invalid/hook", "secret", transport=httpx.MockTransport(bot), clock=lambda: 1700000000)
    assert hook.send("", {"elements": []}) == "" and hook.reply("om_1", {"elements": []}) == ""
    assert seen[0]["timestamp"] == "1700000000" and seen[0]["sign"] and seen[0]["msg_type"] == "interactive"


def test_one_way_to_send_is_chosen(tmp_path: Path) -> None:
    with pytest.raises(SettingsError, match="not both"):
        config_for(tmp_path, webhook_url="https://bot.invalid/hook")
