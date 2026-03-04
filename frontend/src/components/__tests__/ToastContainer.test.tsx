import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, it, expect } from 'vitest';
import { ToastProvider, useToast, type ToastType } from '../../contexts/ToastContext';
import ToastContainer from '../ToastContainer';
import { useEffect } from 'react';

function ToastTrigger({ message, type }: { message: string; type: ToastType }) {
  const { addToast } = useToast();
  useEffect(() => { addToast(message, type); }, [addToast, message, type]);
  return null;
}

function renderWithToast(message: string, type: ToastType) {
  return render(
    <ToastProvider>
      <ToastTrigger message={message} type={type} />
      <ToastContainer />
    </ToastProvider>,
  );
}

describe('ToastContainer', () => {
  it('renders toast messages', () => {
    renderWithToast('Operation succeeded', 'success');
    expect(screen.getByText('Operation succeeded')).toBeInTheDocument();
  });

  it('applies correct class for success type', () => {
    const { container } = renderWithToast('ok', 'success');
    expect(container.querySelector('.toast-success')).toBeInTheDocument();
  });

  it('applies correct class for error type', () => {
    const { container } = renderWithToast('fail', 'error');
    expect(container.querySelector('.toast-error')).toBeInTheDocument();
  });

  it('applies correct class for info type', () => {
    const { container } = renderWithToast('note', 'info');
    expect(container.querySelector('.toast-info')).toBeInTheDocument();
  });

  it('applies correct class for warning type', () => {
    const { container } = renderWithToast('warn', 'warning');
    expect(container.querySelector('.toast-warning')).toBeInTheDocument();
  });

  it('close button removes the toast', async () => {
    renderWithToast('goodbye', 'info');
    expect(screen.getByText('goodbye')).toBeInTheDocument();
    await userEvent.click(screen.getByLabelText('Dismiss'));
    expect(screen.queryByText('goodbye')).not.toBeInTheDocument();
  });
});
