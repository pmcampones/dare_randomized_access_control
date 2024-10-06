package accesscontrolapp

import (
	"fmt"
	"github.com/google/uuid"
)

type Msg struct {
	Issuer  uuid.UUID
	Content string
}

type User struct {
	Id     uuid.UUID
	Points uint32
}

type App struct {
	users map[uuid.UUID]*User
	msgs  []Msg
}

func ExecuteCRDT(crdt *CRDT) (*App, error) {
	app := NewApp()
	for _, op := range crdt.GetOperationList() {
		switch op.kind {
		case Init:
			err := execInit(op, app)
			if err != nil {
				return app, err
			}
		case Add:
			err := execAdd(op, app)
			if err != nil {
				return app, err
			}
		case Rem:
			err := execRem(op, app)
			if err != nil {
				return app, err
			}
		case Post:
			err := execPost(op, app)
			if err != nil {
				return app, err
			}
		default:
			return app, fmt.Errorf("unhandled operation type")
		}
	}
	return app, nil
}

func execPost(op *Op, app *App) error {
	postOp := op.content.(*PostOp)
	err := app.Post(postOp)
	if err != nil {
		return fmt.Errorf("unable to compute post operation: %v", err)
	}
	return nil
}

func execRem(op *Op, app *App) error {
	remOp := op.content.(*RemOp)
	err := app.RemUser(remOp)
	if err != nil {
		return fmt.Errorf("unable to compute remove operation: %v", err)
	}
	return nil
}

func execInit(op *Op, app *App) error {
	initOp := op.content.(*InitOp)
	err := app.Init(initOp)
	if err != nil {
		return fmt.Errorf("unable to compute init operation: %v", err)
	}
	return nil
}

func execAdd(op *Op, app *App) error {
	addOp := op.content.(*AddOp)
	err := app.AddUser(addOp)
	if err != nil {
		return fmt.Errorf("unable to compute add operation: %v", err)
	}
	return nil
}

func NewApp() *App {
	return &App{
		users: make(map[uuid.UUID]*User),
		msgs:  make([]Msg, 0),
	}
}

func (app *App) Init(op *InitOp) error {
	if len(app.users) != 0 {
		return fmt.Errorf("already initialized")
	}
	user := &User{
		Id:     op.initial,
		Points: op.points,
	}
	app.users[op.initial] = user
	return nil
}

func (app *App) AddUser(op *AddOp) error {
	if op.issuer == op.added {
		return fmt.Errorf("user cannot add themselves")
	} else if op.points == 0 {
		return fmt.Errorf("at least a single point must be given")
	}
	issuer := app.users[op.issuer]
	if issuer == nil {
		return fmt.Errorf("operation issuer is not a user")
	} else if issuer.Points <= op.points {
		return fmt.Errorf("issuer cannot give more points than what they have")
	}
	if app.users[op.added] != nil {
		return fmt.Errorf("added user already exists")
	}
	issuer.Points -= op.points
	added := &User{
		Id:     op.added,
		Points: op.points,
	}
	app.users[op.added] = added
	return nil
}

func (app *App) RemUser(op *RemOp) error {
	if op.issuer == op.removed {
		return fmt.Errorf("user cannot remove themselves")
	}
	issuer := app.users[op.issuer]
	removed := app.users[op.removed]
	if issuer == nil {
		return fmt.Errorf("operation issuer is not a user")
	} else if removed == nil {
		return fmt.Errorf("removed user is not in the system")
	}
	issuer.Points += removed.Points
	delete(app.users, op.removed)
	return nil
}

func (app *App) Post(op *PostOp) error {
	poster := app.users[op.poster]
	if poster == nil {
		return fmt.Errorf("operation poster is not a user")
	}
	msg := Msg{
		Issuer:  op.poster,
		Content: op.msg,
	}
	app.msgs = append(app.msgs, msg)
	return nil
}
