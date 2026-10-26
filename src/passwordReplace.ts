/* Guard for putting a generated password into an entry's password field.
   An empty field is filled straight away; a field that already holds a
   value is only replaced after the user confirms. Shared by Mac and iOS. */

export const REPLACE_PROMPT = "기존 비밀번호를 새 값으로 바꿀까요?";

export type ReplaceDecision = "apply" | "confirm";

/** What pressing regenerate (or "use") should do for the current field value. */
export function decideReplace(current: string | null | undefined): ReplaceDecision {
  return current != null && current.length > 0 ? "confirm" : "apply";
}

/** Field value after the confirmation is answered. */
export function resolveReplace(current: string | undefined, generated: string, accepted: boolean): string | undefined {
  return accepted ? generated : current;
}
