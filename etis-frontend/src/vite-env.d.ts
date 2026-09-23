/// <reference types="vite/client" />

declare module 'stylis' {
  export const prefixer: (element: unknown, index: number, children: unknown[], callback: unknown) => string | void
}
