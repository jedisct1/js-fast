export declare class FastError extends Error {
    constructor(message: string);
}
export declare class InvalidRadixError extends FastError {
    constructor();
}
export declare class InvalidWordLengthError extends FastError {
    constructor(message?: string);
}
export declare class InvalidSBoxCountError extends FastError {
    constructor();
}
export declare class InvalidBranchDistError extends FastError {
    constructor(message: string);
}
export declare class InvalidLengthError extends FastError {
    constructor();
}
export declare class InvalidValueError extends FastError {
    constructor();
}
export declare class InvalidParametersError extends FastError {
    constructor(message?: string);
}
