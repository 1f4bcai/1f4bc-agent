export type ReleaseAppPromotionContext = Readonly<{
  repository?: string
  eventName?: string
  actor?: string
  actorId?: string
  triggeringActor?: string
  expectedActor?: string
  expectedActorId?: string
}>

export function assertReleaseAppContext(context: ReleaseAppPromotionContext): void

export type CandidateCiExpectation = Readonly<{
  candidateCommit: string
  candidateRef: string
  expectedActor: string
  expectedActorId: string
}>

export type CandidateCiVerification = Readonly<{
  runId: number
  runAttempt: number
  candidateCommit: string
  candidateRef: string
}>

export function assertSuccessfulCandidateCi(
  payload: unknown,
  expected: CandidateCiExpectation,
): CandidateCiVerification

export type ReleaseCandidatePromotionResult = Readonly<{
  baseCommit: string
  candidateCommit: string
  candidateRef: string
  version: string
  shallowCandidate: true
  promoted: boolean
}>

export function promoteReleaseCandidate(options: {
  mode?: 'verify' | 'promote'
  authorityRoot?: string
  baseCommit: string
  candidateCommit: string
  candidateRef: string
  context: ReleaseAppPromotionContext
  fetchRemote?: string
  pushRemote?: string
  allowTestRemote?: boolean
  releaseAppToken?: string
  releasePreflight?: (options: Record<string, unknown>) => Promise<unknown>
  candidateCiCheck?: (options: CandidateCiExpectation) => Promise<CandidateCiVerification>
  hooks?: {
    beforeRefCheck?: () => void | Promise<void>
    beforePush?: () => void | Promise<void>
    afterPush?: () => void | Promise<void>
  }
}): Promise<ReleaseCandidatePromotionResult>
