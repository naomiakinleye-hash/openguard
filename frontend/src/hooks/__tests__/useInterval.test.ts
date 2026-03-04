import { renderHook } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { useInterval } from '../useInterval';

describe('useInterval', () => {
  beforeEach(() => { vi.useFakeTimers(); });
  afterEach(() => { vi.useRealTimers(); });

  it('calls callback after delay', () => {
    const cb = vi.fn();
    renderHook(() => useInterval(cb, 1000));
    expect(cb).not.toHaveBeenCalled();
    vi.advanceTimersByTime(1000);
    expect(cb).toHaveBeenCalledTimes(1);
    vi.advanceTimersByTime(1000);
    expect(cb).toHaveBeenCalledTimes(2);
  });

  it('stops firing when delay is null', () => {
    const cb = vi.fn();
    const { rerender } = renderHook(
      ({ delay }: { delay: number | null }) => useInterval(cb, delay),
      { initialProps: { delay: 500 as number | null } },
    );
    vi.advanceTimersByTime(500);
    expect(cb).toHaveBeenCalledTimes(1);
    rerender({ delay: null });
    vi.advanceTimersByTime(2000);
    expect(cb).toHaveBeenCalledTimes(1);
  });
});
