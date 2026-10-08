import type { TFunction } from 'i18next';
import type { AnalyzeResponse } from './types';
export function explainVerdict(t: TFunction, result: AnalyzeResponse): string {
  return t(`reason.${result.decisive_reason}`, { defaultValue: t('reason.supporting_evidence') });
}
