export type SignPurpose = 'ldp_vc' | 'jwt' | 'mdoc' | 'x509';

export interface SignContext {
  actor?: string;      // who asked (JWT sub / preferred_username)
  authority?: string;  // which authority the caller acts for (claim named by AUTHORITY_CLAIM)
}

// AuthGuard puts the verified JWT payload on request.user.
export function signContextFrom(request: any): SignContext {
  const user = request?.user;
  const claim = process.env.AUTHORITY_CLAIM || 'authority';
  return {
    actor: user?.sub ?? user?.preferred_username,
    authority: user?.[claim],
  };
}
