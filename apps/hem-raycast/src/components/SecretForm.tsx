import { Action, ActionPanel, Clipboard, Form, Icon, showToast, Toast, useNavigation } from "@raycast/api";
import { Fragment, useState } from "react";
import { useCachedPromise } from "@raycast/utils";
import { ACTOR, getClient } from "../hem/config";
import { parseEnvText } from "../hem/env";
import { showErrorToast } from "./toasts";
import { formatRef, isValidSlug, refToProto, ScopeKind, SecretRefParts, slugify } from "../hem/refs";

const VALUE_KEY_RE = /^[a-z0-9_]+$/;
const CUSTOM_GROUP = "__custom__";

interface KvRow {
  id: number;
  key: string;
  value: string;
  /** Original env-var name when the row came from a .env paste. */
  hint?: string;
}

export interface SecretFormProps {
  /** Present when editing an existing secret; scope and name become fixed. */
  initial?: {
    refParts: SecretRefParts;
    description: string;
    group: string;
    requiresApproval: boolean;
    values: Record<string, string>;
  };
  onSaved?: () => void;
}

let rowIdCounter = 1;
function newRow(partial: Partial<KvRow> = {}): KvRow {
  return { id: rowIdCounter++, key: "", value: "", ...partial };
}

export function SecretForm({ initial, onSaved }: SecretFormProps) {
  const { pop } = useNavigation();
  const client = getClient();
  const editing = initial !== undefined;

  const { data: groups } = useCachedPromise(() => getClient().listGroups(), [], { keepPreviousData: true });

  const [scope, setScope] = useState<ScopeKind>(initial?.refParts.scope ?? "global");
  const [project, setProject] = useState(initial?.refParts.project ?? "");
  const [identityId, setIdentityId] = useState(initial?.refParts.identityId ?? "");
  const [name, setName] = useState(initial?.refParts.name ?? "");
  const [description, setDescription] = useState(initial?.description ?? "");
  const [group, setGroup] = useState(initial?.group || "");
  const [customGroup, setCustomGroup] = useState("");
  const [requiresApproval, setRequiresApproval] = useState(initial?.requiresApproval ?? false);
  const [envText, setEnvText] = useState("");
  const [rows, setRows] = useState<KvRow[]>(() =>
    initial
      ? Object.entries(initial.values).map(([key, value]) => newRow({ key, value }))
      : [newRow({ key: "api_key" })],
  );
  const [nameError, setNameError] = useState<string | undefined>();

  const knownGroups = groups ?? [];
  const groupChoices = new Set(knownGroups.map((g) => g.name));
  if (initial?.group) groupChoices.add(initial.group);

  function importEnv() {
    const entries = parseEnvText(envText);
    if (entries.length === 0) {
      showToast({ style: Toast.Style.Failure, title: "No KEY=VALUE lines found in the paste area" });
      return;
    }
    setRows((prev) => {
      const kept = prev.filter((r) => r.key.trim() || r.value.trim());
      return [...kept, ...entries.map((e) => newRow({ key: e.key, value: e.value, hint: e.originalKey }))];
    });
    setEnvText("");
    showToast({
      style: Toast.Style.Success,
      title: `Imported ${entries.length} value${entries.length === 1 ? "" : "s"}`,
    });
  }

  async function submit() {
    const refParts: SecretRefParts = editing
      ? initial.refParts
      : scope === "project"
        ? { scope, project: project.trim(), name: name.trim() }
        : scope === "identity"
          ? { scope, identityId: identityId.trim(), name: name.trim() }
          : { scope, name: name.trim() };

    if (!editing) {
      if (!isValidSlug(refParts.name)) {
        setNameError("Name must match [a-z0-9-]+");
        return;
      }
      if (refParts.scope === "project" && !isValidSlug(refParts.project ?? "")) {
        showToast({ style: Toast.Style.Failure, title: "Project must match [a-z0-9-]+" });
        return;
      }
      if (refParts.scope === "identity" && !isValidSlug(refParts.identityId ?? "")) {
        showToast({ style: Toast.Style.Failure, title: "Identity id must match [a-z0-9-]+" });
        return;
      }
    }

    const values = rows.map((r) => ({ key: r.key.trim(), value: r.value })).filter((r) => r.key && r.value.length > 0);
    if (values.length === 0) {
      showToast({ style: Toast.Style.Failure, title: "At least one key/value pair is required" });
      return;
    }
    const badKey = values.find((v) => !VALUE_KEY_RE.test(v.key));
    if (badKey) {
      showToast({
        style: Toast.Style.Failure,
        title: `Invalid key "${badKey.key}"`,
        message: "Keys must match [a-z0-9_]+",
      });
      return;
    }
    const seen = new Set<string>();
    for (const v of values) {
      if (seen.has(v.key)) {
        showToast({ style: Toast.Style.Failure, title: `Duplicate key "${v.key}"` });
        return;
      }
      seen.add(v.key);
    }

    const groupValue = group === CUSTOM_GROUP ? slugify(customGroup) : group;
    const refStr = formatRef(refParts);
    const toast = await showToast({ style: Toast.Style.Animated, title: `Saving ${refStr}…` });
    try {
      await client.setSecret({
        secret: refToProto(refParts),
        values,
        description: description.trim(),
        requires_approval: requiresApproval,
        group: groupValue,
        actor: ACTOR,
      });
      toast.style = Toast.Style.Success;
      toast.title = `Saved ${refStr}`;
      toast.primaryAction = {
        title: "Copy Ref",
        shortcut: { modifiers: ["cmd", "shift"], key: "c" },
        onAction: () => Clipboard.copy(refStr),
      };
      onSaved?.();
      if (editing) {
        pop();
      } else {
        setRows([newRow({ key: "api_key" })]);
        setName("");
        setDescription("");
      }
    } catch (error) {
      toast.hide();
      showErrorToast(error);
    }
  }

  return (
    <Form
      navigationTitle={editing ? `Edit ${formatRef(initial.refParts)}` : "Add Secret"}
      actions={
        <ActionPanel>
          <Action.SubmitForm title={editing ? "Save Secret" : "Create Secret"} icon={Icon.Check} onSubmit={submit} />
          <Action
            title="Import .Env from Paste Area"
            icon={Icon.Download}
            shortcut={{ modifiers: ["cmd", "shift"], key: "i" }}
            onAction={importEnv}
          />
          <Action
            title="Add Value Row"
            icon={Icon.Plus}
            shortcut={{ modifiers: ["cmd", "shift"], key: "a" }}
            onAction={() => setRows((prev) => [...prev, newRow()])}
          />
          <Action
            title="Remove Last Value Row"
            icon={Icon.Minus}
            shortcut={{ modifiers: ["cmd", "shift"], key: "backspace" }}
            onAction={() => setRows((prev) => (prev.length > 1 ? prev.slice(0, -1) : prev))}
          />
        </ActionPanel>
      }
    >
      {editing ? (
        <Form.Description title="Secret" text={formatRef(initial.refParts)} />
      ) : (
        <>
          <Form.Dropdown id="scope" title="Scope" value={scope} onChange={(v) => setScope(v as ScopeKind)}>
            <Form.Dropdown.Item value="global" title="Global" />
            <Form.Dropdown.Item value="project" title="Project" />
            <Form.Dropdown.Item value="identity" title="Identity" />
          </Form.Dropdown>
          {scope === "project" && (
            <Form.TextField
              id="project"
              title="Project"
              placeholder="globex"
              value={project}
              onChange={(v) => setProject(slugify(v))}
            />
          )}
          {scope === "identity" && (
            <Form.TextField
              id="identityId"
              title="Identity"
              placeholder="tormod"
              value={identityId}
              onChange={(v) => setIdentityId(slugify(v))}
            />
          )}
          <Form.TextField
            id="name"
            title="Name"
            placeholder="anthropic"
            value={name}
            error={nameError}
            onChange={(v) => {
              setName(slugify(v));
              if (nameError && isValidSlug(slugify(v))) setNameError(undefined);
            }}
            info="Lowercase slug: [a-z0-9-]+ (slugified as you type)"
          />
        </>
      )}
      <Form.TextField id="description" title="Description" value={description} onChange={setDescription} />
      <Form.Dropdown id="group" title="Group" value={group} onChange={setGroup}>
        <Form.Dropdown.Item value="" title="No Group" />
        {[...groupChoices].sort().map((g) => (
          <Form.Dropdown.Item key={g} value={g} title={g} icon={Icon.Tag} />
        ))}
        <Form.Dropdown.Item value={CUSTOM_GROUP} title="New Group…" icon={Icon.Plus} />
      </Form.Dropdown>
      {group === CUSTOM_GROUP && (
        <Form.TextField id="customGroup" title="New Group Name" value={customGroup} onChange={setCustomGroup} />
      )}
      <Form.Checkbox
        id="requiresApproval"
        label="Require approval for non-operator reads"
        value={requiresApproval}
        onChange={setRequiresApproval}
      />
      <Form.Separator />
      {rows.map((row, index) => (
        <Fragment key={row.id}>
          <Form.TextField
            id={`key-${row.id}`}
            title={index === 0 ? "Values" : ""}
            placeholder="key (a-z0-9_)"
            value={row.key}
            info={row.hint ? `Imported from ${row.hint}` : undefined}
            onChange={(v) => setRows((prev) => prev.map((r) => (r.id === row.id ? { ...r, key: v } : r)))}
          />
          <Form.PasswordField
            id={`value-${row.id}`}
            title={`Value: ${row.key || "…"}`}
            value={row.value}
            onChange={(v) => setRows((prev) => prev.map((r) => (r.id === row.id ? { ...r, value: v } : r)))}
          />
        </Fragment>
      ))}
      <Form.Separator />
      <Form.TextArea
        id="envPaste"
        title=".env Paste Import"
        placeholder={"Paste KEY=VALUE lines, then ⌘⇧I to explode them into value rows"}
        value={envText}
        onChange={setEnvText}
        info="Keys are lowercased to hem's [a-z0-9_] form; the original name is kept as a hint on the row."
      />
    </Form>
  );
}
