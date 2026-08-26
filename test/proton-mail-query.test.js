import assert from "node:assert/strict";
import test from "node:test";
import "../src/proton/provider.js";
import { ProtonClient } from "../src/proton/client-v2.js";

const cfg = {
  id: "proton-test",
  label: "Proton Test",
  provider: "proton",
  email: "user@example.test",
  credential: "secret",
  mailboxPassword: null,
};

test("Proton message metadata query uses GET parameters instead of draft-create POST", async () => {
  const client = new ProtonClient(cfg, {});
  let capturedPath = "";
  let capturedOptions = null;
  client.request = async (path, options = {}) => {
    capturedPath = path;
    capturedOptions = options;
    return {
      Messages: [{
        ID: "m1",
        Subject: "Hello",
        Sender: { Name: "Sender", Address: "sender@example.test" },
        ToList: [{ Name: "User", Address: "user@example.test" }],
        CCList: [],
        Time: 1700000000,
        Size: 123,
        Unread: 1,
        LabelIDs: ["0"],
        AddressID: "a1",
        NumAttachments: 0,
      }],
    };
  };

  const rows = await client.listMessages({ folder: "INBOX", limit: 1 });
  assert.equal(capturedOptions.method, "GET");
  assert.equal(capturedOptions.body, undefined);
  assert.match(capturedPath, /^\/mail\/v4\/messages\?/);
  const query = new URL(`https://example.test${capturedPath}`).searchParams;
  assert.equal(query.get("LabelID"), "0");
  assert.equal(query.get("Desc"), "1");
  assert.equal(query.get("Page"), "0");
  assert.equal(query.get("PageSize"), "1");
  assert.equal(query.get("Sort"), "Time");
  assert.equal(rows.length, 1);
  assert.equal(rows[0].protonId, "m1");
  assert.equal(rows[0].subject, "Hello");
  assert.equal(rows[0].unread, true);
});

test("searchMessages and folderStatus inherit the corrected GET message query", async () => {
  const client = new ProtonClient(cfg, {});
  const methods = [];
  client.request = async (path, options = {}) => {
    methods.push({ path, method: options.method });
    return { Messages: [] };
  };
  await client.searchMessages({ folder: "INBOX", limit: 1 });
  await client.folderStatus("INBOX");
  assert.equal(methods.length, 2);
  assert.ok(methods.every((row) => row.method === "GET"));
  assert.ok(methods.every((row) => row.path.startsWith("/mail/v4/messages?")));
});
