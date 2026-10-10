import 'express';

declare global {
  namespace Express {
    interface Request {
      user?: { id: string; email: string; plan: 'free' | 'premium'; planSource: string; displayName: string | null };
      session?: { id: string; csrfToken: string };
      extensionTokenId?: string;
    }
  }
}
