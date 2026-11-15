import { MIME_SIGNATURES } from 'stremio/common/CONSTANTS';

const SIGNATURES = MIME_SIGNATURES as Record<string, string[]>;

// MIME types that say nothing about the actual format, so the content is sniffed instead
const GENERIC_MIME_TYPES = ['', 'application/octet-stream', 'text/plain'];

const isFileType = (buffer: ArrayBuffer, type: string) => {
    const signatures = SIGNATURES[type] ?? [];

    return signatures.some((signature) => {
        const array = new Uint8Array(buffer);
        const signatureBuffer = Buffer.from(signature, 'hex');
        const bufferToCompare = array.subarray(0, signatureBuffer.length);

        return Buffer.compare(signatureBuffer, bufferToCompare) === 0;
    });
};

// Trust a specific MIME type reported by the browser; sniff signatures only when it is missing or generic
const getMatchingTypes = (file: File, buffer: ArrayBuffer) => {
    const sniff = GENERIC_MIME_TYPES.includes(file.type);

    return Object.keys(SIGNATURES).filter((type) => type === file.type || (sniff && isFileType(buffer, type)));
};

export {
    isFileType,
    getMatchingTypes,
};
