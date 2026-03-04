import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, it, expect, vi } from 'vitest';
import Pagination from '../Pagination';

describe('Pagination', () => {
  it('renders correct page info', () => {
    render(<Pagination page={2} total={150} pageSize={50} onPageChange={vi.fn()} />);
    expect(screen.getByText('Page 2 of 3')).toBeInTheDocument();
  });

  it('calls onPageChange with page-1 when Prev is clicked', async () => {
    const onPageChange = vi.fn();
    render(<Pagination page={2} total={150} pageSize={50} onPageChange={onPageChange} />);
    await userEvent.click(screen.getByText('← Prev'));
    expect(onPageChange).toHaveBeenCalledWith(1);
  });

  it('calls onPageChange with page+1 when Next is clicked', async () => {
    const onPageChange = vi.fn();
    render(<Pagination page={2} total={150} pageSize={50} onPageChange={onPageChange} />);
    await userEvent.click(screen.getByText('Next →'));
    expect(onPageChange).toHaveBeenCalledWith(3);
  });

  it('disables Prev button on page 1', () => {
    render(<Pagination page={1} total={150} pageSize={50} onPageChange={vi.fn()} />);
    expect(screen.getByText('← Prev')).toBeDisabled();
  });

  it('disables Next button on last page', () => {
    render(<Pagination page={3} total={150} pageSize={50} onPageChange={vi.fn()} />);
    expect(screen.getByText('Next →')).toBeDisabled();
  });
});
