# passport-miniapp
小程序登陆验证


## Install
```shell
npm install passport-miniapp
```
## Usage

### In Nestjs
```js
import { Strategy } from 'passport-miniapp';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class MiniAppStrategy extends PassportStrategy(Strategy) {
  constructor(
    private readonly configService: ConfigService,
  ) {
  super({
    appid: configService.get('appid'),
    secret: configService.get('secret'),
    codeField: 'code',
    passReqToCallback: true,
  });
  }

  async validate(req, retbody): Promise<any> {
    if (retbody.errcode) {
      throw new UnauthorizedException(retbody.errmsg);
    }
    return {
      session_key: retbody.session_key,
      openid: retbody.openid,
      unionid: retbody.unionid,
    };
  }
}

```