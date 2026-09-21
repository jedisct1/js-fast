import { CycleWalkError } from "./errors.ts";

/** Maximum attempts for one segment. */
export const MAX_CYCLE_STEPS = 32;

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
export function cycleWalk(
	input: string,
	step: (value: string) => string,
	inClass: (value: string) => boolean,
	maxSteps: number = MAX_CYCLE_STEPS,
): CycleWalkResult {
	let value = input;
	for (let steps = 1; steps <= maxSteps; steps++) {
		value = step(value);
		if (inClass(value)) return { output: value, steps };
	}
	throw new CycleWalkError();
}
