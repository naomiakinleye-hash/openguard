import { render, screen } from '@testing-library/react';
import { describe, it, expect } from 'vitest';
import MiniBarChart from '../MiniBarChart';

describe('MiniBarChart', () => {
  it('renders label and value', () => {
    render(<MiniBarChart label="T1" value={10} max={100} color="#1d4ed8" />);
    expect(screen.getByText('T1')).toBeInTheDocument();
    expect(screen.getByText('10')).toBeInTheDocument();
  });

  it('calculates width percentage correctly', () => {
    const { container } = render(<MiniBarChart label="T2" value={50} max={100} color="#d97706" />);
    const fill = container.querySelector('.mini-bar-fill') as HTMLElement;
    expect(fill.style.width).toBe('50%');
  });

  it('handles max=0 without crash (shows 0%)', () => {
    const { container } = render(<MiniBarChart label="T0" value={0} max={0} color="#334155" />);
    const fill = container.querySelector('.mini-bar-fill') as HTMLElement;
    expect(fill.style.width).toBe('0%');
  });
});
