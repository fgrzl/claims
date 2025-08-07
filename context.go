package claims

import (
	"context"
)

type userKeyType struct{}

func WithUser(ctx context.Context, user Principal) context.Context {
	return context.WithValue(ctx, userKeyType{}, user)
}

func UserFromContext(ctx context.Context) (Principal, bool) {
	user, ok := ctx.Value(userKeyType{}).(Principal)
	return user, ok
}
