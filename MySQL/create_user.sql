SET @nick_name='シライ', @email='suguster@ca.sge-devel.coms', @password='suguster';

begin;
INSERT INTO users (nick_name,email,passhash) VALUES (@nick_name,@email,'');

INSERT INTO salts (user_id,salt) VALUES (LAST_INSERT_ID(),FLOOR(MICROSECOND(NOW(6)) * RAND()));
UPDATE users u JOIN salts s ON u.id=s.user_id SET passhash=SHA2(CONCAT(@password, s.salt), 512) WHERE id=LAST_INSERT_ID();

commit;
