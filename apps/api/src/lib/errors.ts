export class HttpError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
    public details?: unknown,
  ) {
    super(message);
  }
}

export const notFound = (what = 'Resource') => new HttpError(404, 'not_found', `${what} not found`);
export const forbidden = (message = 'You do not have access to this resource') =>
  new HttpError(403, 'forbidden', message);
export const badRequest = (message: string, code = 'bad_request') => new HttpError(400, code, message);
export const premiumRequired = () =>
  new HttpError(403, 'premium_required', 'This feature requires a Premium plan. All Free features remain available.');
