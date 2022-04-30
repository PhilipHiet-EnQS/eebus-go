package usecase

import (
	"fmt"
	"time"

	"github.com/DerAndereAndi/eebus-go/spine"
	"github.com/DerAndereAndi/eebus-go/spine/model"
	"github.com/ahmetb/go-linq/v3"
)

var entityTypeActorMap = map[model.EntityTypeType]model.UseCaseActorType{
	model.EntityTypeTypeEVSE: model.UseCaseActorTypeEVSE,
	model.EntityTypeTypeCEM:  model.UseCaseActorTypeCEM,
}

var useCaseValidActorsMap = map[model.UseCaseNameType][]model.UseCaseActorType{
	model.UseCaseNameTypeEVSECommissioningAndConfiguration: {model.UseCaseActorTypeEVSE, model.UseCaseActorTypeCEM},
}

type UseCaseImpl struct {
	Entity *spine.EntityLocalImpl
	Actor  model.UseCaseActorType

	name            model.UseCaseNameType
	scenarioSupport []model.UseCaseScenarioSupportType
}

func NewUseCase(entity *spine.EntityLocalImpl, ucEnumType model.UseCaseNameType, scenarioSupport []model.UseCaseScenarioSupportType) *UseCaseImpl {
	checkArguments(*entity.EntityImpl, ucEnumType)

	actor := entityTypeActorMap[entity.EntityType()]

	ucManager := entity.Device().UseCaseManager()
	ucManager.Add(actor, ucEnumType, scenarioSupport)

	return &UseCaseImpl{
		Entity:          entity,
		Actor:           actor,
		name:            model.UseCaseNameType(ucEnumType),
		scenarioSupport: scenarioSupport,
	}
}

func checkArguments(entity spine.EntityImpl, ucEnumType model.UseCaseNameType) {
	actor := entityTypeActorMap[entity.EntityType()]
	if actor == "" {
		panic(fmt.Errorf("cannot derive actor for entity type '%s'", entity.EntityType()))
	}

	if !linq.From(useCaseValidActorsMap[ucEnumType]).Contains(actor) {
		panic(fmt.Errorf("the actor '%s' is not valid for the use case '%s'", actor, ucEnumType))
	}
}

func waitForRequest[T any](c chan T, maxDelay time.Duration) *T {
	timeout := time.After(maxDelay)

	select {
	case data := <-c:
		return &data
	case <-timeout:
		return nil
	}
}