export declare class FastError extends Error {
}
export declare class InvalidRadixError extends FastError {
    name: string;
    constructor();
}
export declare class InvalidWordLengthError extends FastError {
    name: string;
    constructor(message?: string);
}
export declare class InvalidSBoxCountError extends FastError {
    name: string;
    constructor();
}
export declare class InvalidBranchDistError extends FastError {
    name: string;
}
export declare class InvalidLengthError extends FastError {
    name: string;
    constructor();
}
export declare class InvalidValueError extends FastError {
    name: string;
    constructor();
}
export declare class InvalidParametersError extends FastError {
    name: string;
    constructor(message?: string);
}
