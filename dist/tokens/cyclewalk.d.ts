/** Maximum attempts for one segment. */
export declare const MAX_CYCLE_STEPS = 32;
export interface CycleWalkResult {
    output: string;
    /** Number of calls to `step`; always at least one. */
    steps: number;
}
/**
 * Keep applying `step` until `inClass` accepts the result.
 *
 * To keep the walk reversible, `input` must already satisfy `inClass`, and
 * `step` must be reversible.
 * A `CycleWalkError` is thrown if no result is found within `maxSteps`.
 */
export declare function cycleWalk(input: string, step: (value: string) => string, inClass: (value: string) => boolean, maxSteps?: number): CycleWalkResult;
