export const identity = <T,>(value: T): T => value;

function sealed(target: Function) {
  return target;
}

@sealed
export class Box {
  #hidden = 10n;
  label?: { text?: string };

  text(fallback: string): string {
    return this.label?.text ?? fallback;
  }

  get size(): bigint {
    return this.#hidden;
  }
}
