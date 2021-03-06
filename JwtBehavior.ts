import {getService} from 'dok-ts';
import {BaseError} from 'dok-ts/base/BaseError';

export async function JwtBehavior(ctx) {
  const {headers} = ctx.get();
  const jwtService = getService('JwtService');

  if (!headers.authorization
    || !headers.authorization.length
    || headers.authorization.split(' ')[0] !== 'Bearer'
  ) {
    throw new BaseError(403, 'global.permission_deny')
  }

  const token = headers.authorization.split(' ')[1];

  ctx.set('jwt', {
    token,
    payload: await jwtService.verify(token)
  })

}