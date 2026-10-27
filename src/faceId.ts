export function faceIdReasonMessage(reason?: string | null): string | null {
  if (reason === "rebooted") return "기기를 다시 시작해 마스터 비밀번호가 필요합니다.";
  if (reason === "expired") return "보안을 위해 7일마다 마스터 비밀번호가 필요합니다.";
  if (reason === "itemMissing" || reason === "invalidated" || reason === "notFound") {
    return "Face ID 정보가 바뀌었거나 없어 Face ID 잠금 해제를 껐습니다. 마스터 비밀번호를 입력하세요.";
  }
  if (reason === "firstSetup") return "처음 설정할 때는 마스터 비밀번호가 필요합니다.";
  return null;
}
