import * as passport from 'passport';
import { Request } from 'express';
import * as https from 'https';
import * as iconv from 'iconv-lite';

export class Strategy extends passport.Strategy {
  private readonly verify: any;
  private readonly appid: string;
  private readonly secret: string;
  private readonly codeField: string;
  private readonly passReqToCallback: boolean;
  constructor(options: ConfigOpt, verify: VerifyFunction | VerifyFunctionWithRequest) {
    super();
    this.name = 'miniapp';
    this.verify = verify;
    this.appid = options.appid;
    this.secret = options.secret;
    this.codeField = options.codeField || 'code';
    this.passReqToCallback = options.passReqToCallback || false;
  }

  verified(err: any, user: any, info: any) {
    if (err) { return this.error(err); }
    if (!user) { return this.fail(info); }
    this.success(user, info);
  }

  authenticate(req: Request) {
    if (!this.appid || !this.secret) {
      return this.fail(`Lost appid or secret Params !`);
    }
    const wxcode = req.body.code || req.query.code;
    if (!wxcode) {
      return this.fail(`Lost ${this.codeField} params !`, 400);
    }

    // tslint:disable-next-line: max-line-length
    https.get(`https://api.weixin.qq.com/sns/jscode2session?appid=${this.appid}&secret=${this.secret}&js_code=${wxcode}&grant_type=authorization_code`, res => {
      const chunks: Buffer[] = [];
      res.on('data', chunk => chunks.push(chunk));
      res.on('end', () => {
        try {
          if (res.statusCode === 200) {
            const buff = Buffer.concat(chunks);
            const contentType: string = res.headers['content-type'] || '';
            const matchCharset = contentType.match(/(?:charset=)(\w+)/) || [];
            const body = iconv.decode(buff, matchCharset[1] || 'utf8');
            const retbody = JSON.parse(body);
            if (this.passReqToCallback) {
              this.verify(req, retbody, this.verified.bind(this));
            } else {
              this.verify(retbody, this.verified.bind(this));
            }
          } else {
            return this.fail('Network Request Error');
          }
        } catch (ex) {
          return this.error(ex);
        }
      });
    });
  }
}

interface ConfigOpt {
  appid: string;
  secret: string;
  codeField?: string;
  passReqToCallback?: boolean;
}

interface Retbody {
  session_key?: string;
  openid?: string;
  errcode?: number;
  errmsg?: string;
  unionid?: string;
}

interface IVerifyOptions {
  message: string;
}
interface VerifyFunction {
  (
    retbody: Retbody,
    done: (error: any, user?: any, options?: IVerifyOptions) => void
  ): void;
}

interface VerifyFunctionWithRequest {
  (
    req: Request,
    retbody: Retbody,
    done: (error: any, user?: any, options?: IVerifyOptions) => void
  ): void;
}