import { describe, expect, it, vi, afterEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router';
import { download, ApiError } from './api';
import { StatusActions } from './pages/Remediation';
import { DasiGauge, ReputationBadge } from './components/ui';
import type { RemediationItem } from './api';

afterEach(() => vi.restoreAllMocks());

const wrap = (ui: React.ReactNode) =>
  render(
    <QueryClientProvider client={new QueryClient()}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );

const item = (over: Partial<RemediationItem> = {}): RemediationItem => ({
  id: 'i1', account_id: 'a1', action_type: 'change_password', title: 'Change your X password', description: 'd', priority: 1,
  official_url: 'https://x.example/settings', url_kind: 'curated_official', status: 'recommended', status_note: null, service_name: 'X', verifiable: true, ...over,
});

describe('download()', () => {
  it('refuses to report success when the server returns JSON instead of a workbook', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('{"ok":true}', { status: 200, headers: { 'content-type': 'application/json' } }));
    await expect(download('/api/reports/security.xlsx', 'r.xlsx')).rejects.toBeInstanceOf(ApiError);
  });
  it('surfaces server errors', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('{"error":"internal_error","message":"boom"}', { status: 500 }));
    await expect(download('/x', 'r.xlsx')).rejects.toMatchObject({ message: 'boom' });
  });
  it('surfaces network failures', async () => {
    vi.spyOn(globalThis, 'fetch').mockRejectedValue(new TypeError('fail'));
    await expect(download('/x', 'r.xlsx')).rejects.toMatchObject({ code: 'network_error' });
  });
});

describe('StatusActions', () => {
  it('offers only valid next steps for a recommendation, with an official link', () => {
    wrap(<StatusActions item={item()} />);
    expect(screen.getByRole('link', { name: /Open X settings/ })).toHaveAttribute('rel', 'noopener noreferrer');
    expect(screen.getByText('Official page (curated)')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Start' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Check for confirmation/ })).toBeNull();
  });
  it('labels user-reported completion honestly and offers verification', () => {
    wrap(<StatusActions item={item({ status: 'user_reported_complete' })} />);
    expect(screen.getByText('Done (you reported)')).toBeInTheDocument();
    expect(screen.getByText(/cannot see changes on other websites/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Check for confirmation/ })).toBeInTheDocument();
  });
  it('labels well-known links as possibly unsupported', () => {
    wrap(<StatusActions item={item({ url_kind: 'well_known_standard' })} />);
    expect(screen.getByText(/may not support it/)).toBeInTheDocument();
  });
  it('shows the server error when a change fails', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('{"error":"invalid_transition","message":"Cannot change status"}', { status: 409 }));
    wrap(<StatusActions item={item()} />);
    await userEvent.click(screen.getByRole('button', { name: 'Start' }));
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('Cannot change status'));
  });
});

describe('status visuals', () => {
  it('never relies on colour alone', () => {
    render(<><DasiGauge score={null} level="unknown" /><ReputationBadge status="red" /></>);
    expect(screen.getByRole('img', { name: 'DASI not yet calculated' })).toBeInTheDocument();
    expect(screen.getByText('Known malicious')).toBeInTheDocument();
  });
});
