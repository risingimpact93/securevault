import { describe, expect, it } from "vitest";
import { decideReplace, resolveReplace, REPLACE_PROMPT } from "./passwordReplace";

describe("decideReplace", () => {
  it("fills an empty field without asking", () => {
    expect(decideReplace("")).toBe("apply");
    expect(decideReplace(undefined)).toBe("apply");
    expect(decideReplace(null)).toBe("apply");
  });
  it("asks before replacing an existing value", () => {
    expect(decideReplace("hunter2")).toBe("confirm");
    expect(decideReplace(" ")).toBe("confirm");
  });
});

describe("resolveReplace", () => {
  it("keeps the old value on cancel", () => {
    expect(resolveReplace("old-pw", "new-pw", false)).toBe("old-pw");
  });
  it("uses the new value on 바꾸기", () => {
    expect(resolveReplace("old-pw", "new-pw", true)).toBe("new-pw");
  });
  it("uses the agreed prompt text", () => {
    expect(REPLACE_PROMPT).toBe("기존 비밀번호를 새 값으로 바꿀까요?");
  });
});
