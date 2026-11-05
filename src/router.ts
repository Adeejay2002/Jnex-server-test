import type { Ctx } from "./types";

export type Handler = (ctx: Ctx, params: Record<string, string>) => Promise<Response>;

interface Route {
  method: string;
  regex: RegExp;
  keys: string[];
  handler: Handler;
}

export class Router {
  private routes: Route[] = [];

  add(method: string, path: string, handler: Handler): void {
    const keys: string[] = [];
    const pattern = path.replace(/:[A-Za-z]+/g, (m) => {
      keys.push(m.slice(1));
      return "([^/]+)";
    });
    this.routes.push({ method, regex: new RegExp(`^${pattern}$`), keys, handler });
  }

  // returns the handler + params, or whether the path exists for another method
  match(method: string, pathname: string): { handler: Handler; params: Record<string, string> } | "method_not_allowed" | null {
    let pathExists = false;
    for (const r of this.routes) {
      const m = r.regex.exec(pathname);
      if (!m) continue;
      pathExists = true;
      if (r.method !== method) continue;
      const params: Record<string, string> = {};
      r.keys.forEach((k, i) => (params[k] = decodeURIComponent(m[i + 1])));
      return { handler: r.handler, params };
    }
    return pathExists ? "method_not_allowed" : null;
  }
}
