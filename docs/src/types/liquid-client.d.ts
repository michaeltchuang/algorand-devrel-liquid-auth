declare module '@algorandfoundation/liquid-client/signal' {
  export class SignalClient {
    constructor(url: string);
    static generateRequestId(): string;
    on(event: string, callback: (data: any) => void): void;
    peer(requestId: string, type: string): Promise<any>;
    qrCode(): Promise<string>;
    deepLink(requestId: string): string;
    close(): void;
  }
}

declare module '@algorandfoundation/liquid-client/encoding' {
  export function toBase64URL(data: Uint8Array): string;
}
