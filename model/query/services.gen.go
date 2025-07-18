// Code generated by gorm.io/gen. DO NOT EDIT.
// Code generated by gorm.io/gen. DO NOT EDIT.
// Code generated by gorm.io/gen. DO NOT EDIT.

package query

import (
	"context"

	"github.com/khanghh/cas-go/model"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/schema"

	"gorm.io/gen"
	"gorm.io/gen/field"

	"gorm.io/plugin/dbresolver"
)

func newService(db *gorm.DB, opts ...gen.DOOption) service {
	_service := service{}

	_service.serviceDo.UseDB(db, opts...)
	_service.serviceDo.UseModel(&model.Service{})

	tableName := _service.serviceDo.TableName()
	_service.ALL = field.NewAsterisk(tableName)
	_service.ID = field.NewUint(tableName, "id")
	_service.CreatedAt = field.NewTime(tableName, "created_at")
	_service.UpdatedAt = field.NewTime(tableName, "updated_at")
	_service.DeletedAt = field.NewField(tableName, "deleted_at")
	_service.DisplayName = field.NewString(tableName, "display_name")
	_service.ServiceUrl = field.NewString(tableName, "service_url")
	_service.CallbackUrl = field.NewString(tableName, "callback_url")
	_service.AutoLogin = field.NewBool(tableName, "auto_login")
	_service.PublicKey = field.NewString(tableName, "public_key")

	_service.fillFieldMap()

	return _service
}

type service struct {
	serviceDo

	ALL         field.Asterisk
	ID          field.Uint
	CreatedAt   field.Time
	UpdatedAt   field.Time
	DeletedAt   field.Field
	DisplayName field.String
	ServiceUrl  field.String
	CallbackUrl field.String
	AutoLogin   field.Bool
	PublicKey   field.String

	fieldMap map[string]field.Expr
}

func (s service) Table(newTableName string) *service {
	s.serviceDo.UseTable(newTableName)
	return s.updateTableName(newTableName)
}

func (s service) As(alias string) *service {
	s.serviceDo.DO = *(s.serviceDo.As(alias).(*gen.DO))
	return s.updateTableName(alias)
}

func (s *service) updateTableName(table string) *service {
	s.ALL = field.NewAsterisk(table)
	s.ID = field.NewUint(table, "id")
	s.CreatedAt = field.NewTime(table, "created_at")
	s.UpdatedAt = field.NewTime(table, "updated_at")
	s.DeletedAt = field.NewField(table, "deleted_at")
	s.DisplayName = field.NewString(table, "display_name")
	s.ServiceUrl = field.NewString(table, "service_url")
	s.CallbackUrl = field.NewString(table, "callback_url")
	s.AutoLogin = field.NewBool(table, "auto_login")
	s.PublicKey = field.NewString(table, "public_key")

	s.fillFieldMap()

	return s
}

func (s *service) GetFieldByName(fieldName string) (field.OrderExpr, bool) {
	_f, ok := s.fieldMap[fieldName]
	if !ok || _f == nil {
		return nil, false
	}
	_oe, ok := _f.(field.OrderExpr)
	return _oe, ok
}

func (s *service) fillFieldMap() {
	s.fieldMap = make(map[string]field.Expr, 9)
	s.fieldMap["id"] = s.ID
	s.fieldMap["created_at"] = s.CreatedAt
	s.fieldMap["updated_at"] = s.UpdatedAt
	s.fieldMap["deleted_at"] = s.DeletedAt
	s.fieldMap["display_name"] = s.DisplayName
	s.fieldMap["service_url"] = s.ServiceUrl
	s.fieldMap["callback_url"] = s.CallbackUrl
	s.fieldMap["auto_login"] = s.AutoLogin
	s.fieldMap["public_key"] = s.PublicKey
}

func (s service) clone(db *gorm.DB) service {
	s.serviceDo.ReplaceConnPool(db.Statement.ConnPool)
	return s
}

func (s service) replaceDB(db *gorm.DB) service {
	s.serviceDo.ReplaceDB(db)
	return s
}

type serviceDo struct{ gen.DO }

func (s serviceDo) Debug() *serviceDo {
	return s.withDO(s.DO.Debug())
}

func (s serviceDo) WithContext(ctx context.Context) *serviceDo {
	return s.withDO(s.DO.WithContext(ctx))
}

func (s serviceDo) ReadDB() *serviceDo {
	return s.Clauses(dbresolver.Read)
}

func (s serviceDo) WriteDB() *serviceDo {
	return s.Clauses(dbresolver.Write)
}

func (s serviceDo) Session(config *gorm.Session) *serviceDo {
	return s.withDO(s.DO.Session(config))
}

func (s serviceDo) Clauses(conds ...clause.Expression) *serviceDo {
	return s.withDO(s.DO.Clauses(conds...))
}

func (s serviceDo) Returning(value interface{}, columns ...string) *serviceDo {
	return s.withDO(s.DO.Returning(value, columns...))
}

func (s serviceDo) Not(conds ...gen.Condition) *serviceDo {
	return s.withDO(s.DO.Not(conds...))
}

func (s serviceDo) Or(conds ...gen.Condition) *serviceDo {
	return s.withDO(s.DO.Or(conds...))
}

func (s serviceDo) Select(conds ...field.Expr) *serviceDo {
	return s.withDO(s.DO.Select(conds...))
}

func (s serviceDo) Where(conds ...gen.Condition) *serviceDo {
	return s.withDO(s.DO.Where(conds...))
}

func (s serviceDo) Order(conds ...field.Expr) *serviceDo {
	return s.withDO(s.DO.Order(conds...))
}

func (s serviceDo) Distinct(cols ...field.Expr) *serviceDo {
	return s.withDO(s.DO.Distinct(cols...))
}

func (s serviceDo) Omit(cols ...field.Expr) *serviceDo {
	return s.withDO(s.DO.Omit(cols...))
}

func (s serviceDo) Join(table schema.Tabler, on ...field.Expr) *serviceDo {
	return s.withDO(s.DO.Join(table, on...))
}

func (s serviceDo) LeftJoin(table schema.Tabler, on ...field.Expr) *serviceDo {
	return s.withDO(s.DO.LeftJoin(table, on...))
}

func (s serviceDo) RightJoin(table schema.Tabler, on ...field.Expr) *serviceDo {
	return s.withDO(s.DO.RightJoin(table, on...))
}

func (s serviceDo) Group(cols ...field.Expr) *serviceDo {
	return s.withDO(s.DO.Group(cols...))
}

func (s serviceDo) Having(conds ...gen.Condition) *serviceDo {
	return s.withDO(s.DO.Having(conds...))
}

func (s serviceDo) Limit(limit int) *serviceDo {
	return s.withDO(s.DO.Limit(limit))
}

func (s serviceDo) Offset(offset int) *serviceDo {
	return s.withDO(s.DO.Offset(offset))
}

func (s serviceDo) Scopes(funcs ...func(gen.Dao) gen.Dao) *serviceDo {
	return s.withDO(s.DO.Scopes(funcs...))
}

func (s serviceDo) Unscoped() *serviceDo {
	return s.withDO(s.DO.Unscoped())
}

func (s serviceDo) Create(values ...*model.Service) error {
	if len(values) == 0 {
		return nil
	}
	return s.DO.Create(values)
}

func (s serviceDo) CreateInBatches(values []*model.Service, batchSize int) error {
	return s.DO.CreateInBatches(values, batchSize)
}

// Save : !!! underlying implementation is different with GORM
// The method is equivalent to executing the statement: db.Clauses(clause.OnConflict{UpdateAll: true}).Create(values)
func (s serviceDo) Save(values ...*model.Service) error {
	if len(values) == 0 {
		return nil
	}
	return s.DO.Save(values)
}

func (s serviceDo) First() (*model.Service, error) {
	if result, err := s.DO.First(); err != nil {
		return nil, err
	} else {
		return result.(*model.Service), nil
	}
}

func (s serviceDo) Take() (*model.Service, error) {
	if result, err := s.DO.Take(); err != nil {
		return nil, err
	} else {
		return result.(*model.Service), nil
	}
}

func (s serviceDo) Last() (*model.Service, error) {
	if result, err := s.DO.Last(); err != nil {
		return nil, err
	} else {
		return result.(*model.Service), nil
	}
}

func (s serviceDo) Find() ([]*model.Service, error) {
	result, err := s.DO.Find()
	return result.([]*model.Service), err
}

func (s serviceDo) FindInBatch(batchSize int, fc func(tx gen.Dao, batch int) error) (results []*model.Service, err error) {
	buf := make([]*model.Service, 0, batchSize)
	err = s.DO.FindInBatches(&buf, batchSize, func(tx gen.Dao, batch int) error {
		defer func() { results = append(results, buf...) }()
		return fc(tx, batch)
	})
	return results, err
}

func (s serviceDo) FindInBatches(result *[]*model.Service, batchSize int, fc func(tx gen.Dao, batch int) error) error {
	return s.DO.FindInBatches(result, batchSize, fc)
}

func (s serviceDo) Attrs(attrs ...field.AssignExpr) *serviceDo {
	return s.withDO(s.DO.Attrs(attrs...))
}

func (s serviceDo) Assign(attrs ...field.AssignExpr) *serviceDo {
	return s.withDO(s.DO.Assign(attrs...))
}

func (s serviceDo) Joins(fields ...field.RelationField) *serviceDo {
	for _, _f := range fields {
		s = *s.withDO(s.DO.Joins(_f))
	}
	return &s
}

func (s serviceDo) Preload(fields ...field.RelationField) *serviceDo {
	for _, _f := range fields {
		s = *s.withDO(s.DO.Preload(_f))
	}
	return &s
}

func (s serviceDo) FirstOrInit() (*model.Service, error) {
	if result, err := s.DO.FirstOrInit(); err != nil {
		return nil, err
	} else {
		return result.(*model.Service), nil
	}
}

func (s serviceDo) FirstOrCreate() (*model.Service, error) {
	if result, err := s.DO.FirstOrCreate(); err != nil {
		return nil, err
	} else {
		return result.(*model.Service), nil
	}
}

func (s serviceDo) FindByPage(offset int, limit int) (result []*model.Service, count int64, err error) {
	result, err = s.Offset(offset).Limit(limit).Find()
	if err != nil {
		return
	}

	if size := len(result); 0 < limit && 0 < size && size < limit {
		count = int64(size + offset)
		return
	}

	count, err = s.Offset(-1).Limit(-1).Count()
	return
}

func (s serviceDo) ScanByPage(result interface{}, offset int, limit int) (count int64, err error) {
	count, err = s.Count()
	if err != nil {
		return
	}

	err = s.Offset(offset).Limit(limit).Scan(result)
	return
}

func (s serviceDo) Scan(result interface{}) (err error) {
	return s.DO.Scan(result)
}

func (s serviceDo) Delete(models ...*model.Service) (result gen.ResultInfo, err error) {
	return s.DO.Delete(models)
}

func (s *serviceDo) withDO(do gen.Dao) *serviceDo {
	s.DO = *do.(*gen.DO)
	return s
}
