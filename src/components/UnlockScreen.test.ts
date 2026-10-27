import { describe, expect, it } from "vitest";
import { faceIdReasonMessage } from "../faceId";

describe("faceIdReasonMessage", () => {
  it("explains reboot and the 7-day window in Korean", () => {
    expect(faceIdReasonMessage("rebooted")).toBe("기기를 다시 시작해 마스터 비밀번호가 필요합니다.");
    expect(faceIdReasonMessage("expired")).toBe("보안을 위해 7일마다 마스터 비밀번호가 필요합니다.");
  });

  it("explains a missing or invalidated Face ID item", () => {
    const msg = "Face ID 정보가 바뀌었거나 없어 Face ID 잠금 해제를 껐습니다. 마스터 비밀번호를 입력하세요.";
    expect(faceIdReasonMessage("itemMissing")).toBe(msg);
    expect(faceIdReasonMessage("invalidated")).toBe(msg);
    expect(faceIdReasonMessage("notFound")).toBe(msg);
  });
});
