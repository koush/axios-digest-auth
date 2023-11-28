"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const crypto = require("crypto");
const url = require("url");
const axios = require("axios");
const authHeader = require("auth-header");
// from auth-header, but not exposed
const quote = (str) => `"${str.replace(/"/g, '\\"')}"`;
function takeFirst(value) {
    if (value.constructor === Array)
        return value[0];
    return value;
}
class AxiosDigestAuth {
    constructor({ axios: axiosInst, password, username }) {
        this.axios = axiosInst ? axiosInst : axios.default;
        this.count = 0;
        this.password = password;
        this.username = username;
    }
    async request(opts) {
        var _a, _b;
        try {
            return await this.axios.request(opts);
        }
        catch (resp1) {
            if (resp1.response === undefined
                || resp1.response.status !== 401
                || !((_a = resp1.response.headers["www-authenticate"]) === null || _a === void 0 ? void 0 : _a.includes('nonce'))) {
                throw resp1;
            }
            // const authDetails = resp1.response.headers['www-authenticate'].split(',').map((v: string) => v.split('='));
            const wwwAuthenticate = resp1.response.headers['www-authenticate'];
            const parsedAuthorization = authHeader.parse(wwwAuthenticate);
            ++this.count;
            const nonceCount = ('00000000' + this.count).slice(-8);
            const cnonce = crypto.randomBytes(24).toString('hex');
            // const realm = authDetails.find((el: any) => el[0].toLowerCase().indexOf("realm") > -1)[1].replace(/"/g, '');
            const realm = takeFirst(parsedAuthorization.params['realm']);
            // const nonce = authDetails.find((el: any) => el[0].toLowerCase().indexOf("nonce") > -1)[1].replace(/"/g, '');
            const nonce = takeFirst(parsedAuthorization.params['nonce']);
            const opaque = parsedAuthorization.params['opaque'] == null
                ? undefined
                : takeFirst(parsedAuthorization.params['opaque']);
            const ha1 = crypto.createHash('md5').update(`${this.username}:${realm}:${this.password}`).digest('hex');
            const path = url.parse(opts.url).pathname;
            const ha2 = crypto.createHash('md5').update(`${(_b = opts.method) !== null && _b !== void 0 ? _b : "GET"}:${path}`).digest('hex');
            const response = crypto.createHash('md5').update(`${ha1}:${nonce}:${nonceCount}:${cnonce}:auth:${ha2}`).digest('hex');
            // removed params that shouldnt be quoted
            const params = {
                username: this.username,
                realm,
                nonce,
                uri: path || '',
                // qop: 'auth',
                algorithm: 'MD5',
                response,
                // nc: nonceCount,
                opaque,
                cnonce,
            };
            parsedAuthorization;
            const paramsString = Object.entries(params).map(([key, value]) => `${key}=${value != null && quote(value)}`).join(', ');
            // Added unquoted params manually
            const authorization = `Digest ${paramsString}, qop=auth, nc=${nonceCount}}`;
            if (opts.headers) {
                opts.headers["authorization"] = authorization;
            }
            else {
                opts.headers = { authorization };
            }
            return this.axios.request(opts);
        }
    }
}
exports.default = AxiosDigestAuth;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXguanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi9zcmMvaW5kZXgudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7QUFBQSxpQ0FBaUM7QUFDakMsMkJBQTJCO0FBQzNCLCtCQUErQjtBQUMvQiwwQ0FBMEM7QUFFMUMsb0NBQW9DO0FBQ3BDLE1BQU0sS0FBSyxHQUFHLENBQUMsR0FBVyxFQUFVLEVBQUUsQ0FBQyxJQUFJLEdBQUcsQ0FBQyxPQUFPLENBQUMsSUFBSSxFQUFFLEtBQUssQ0FBQyxHQUFHLENBQUM7QUFpQnZFLFNBQVMsU0FBUyxDQUFDLEtBQXdCO0lBQ3pDLElBQUksS0FBSyxDQUFDLFdBQVcsS0FBSyxLQUFLO1FBQzdCLE9BQU8sS0FBSyxDQUFDLENBQUMsQ0FBQyxDQUFDO0lBQ2xCLE9BQU8sS0FBZSxDQUFDO0FBQ3pCLENBQUM7QUFFRCxNQUFxQixlQUFlO0lBT2xDLFlBQVksRUFBRSxLQUFLLEVBQUUsU0FBUyxFQUFFLFFBQVEsRUFBRSxRQUFRLEVBQXVCO1FBQ3ZFLElBQUksQ0FBQyxLQUFLLEdBQUcsU0FBUyxDQUFDLENBQUMsQ0FBQyxTQUFTLENBQUMsQ0FBQyxDQUFDLEtBQUssQ0FBQyxPQUFPLENBQUM7UUFDbkQsSUFBSSxDQUFDLEtBQUssR0FBRyxDQUFDLENBQUM7UUFDZixJQUFJLENBQUMsUUFBUSxHQUFHLFFBQVEsQ0FBQztRQUN6QixJQUFJLENBQUMsUUFBUSxHQUFHLFFBQVEsQ0FBQztJQUMzQixDQUFDO0lBRU0sS0FBSyxDQUFDLE9BQU8sQ0FBQyxJQUE4Qjs7UUFDakQsSUFBSTtZQUNGLE9BQU8sTUFBTSxJQUFJLENBQUMsS0FBSyxDQUFDLE9BQU8sQ0FBQyxJQUFJLENBQUMsQ0FBQztTQUN2QztRQUFDLE9BQU8sS0FBVSxFQUFFO1lBQ25CLElBQUksS0FBSyxDQUFDLFFBQVEsS0FBSyxTQUFTO21CQUMzQixLQUFLLENBQUMsUUFBUSxDQUFDLE1BQU0sS0FBSyxHQUFHO21CQUM3QixDQUFDLENBQUEs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