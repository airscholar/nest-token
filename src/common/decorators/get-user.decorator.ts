import { createParamDecorator, ExecutionContext } from "@nestjs/common";

export const GetUser = createParamDecorator((data: string | undefined, contenxt: ExecutionContext) => {
    const request = contenxt.switchToHttp().getRequest();

    if(!data) return request.user;

    return request.user[data];
})