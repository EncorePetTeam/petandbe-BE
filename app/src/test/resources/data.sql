INSERT INTO address (address_code, state_name, city_name)
VALUES ('05300', '서울특별시', '관악구');
INSERT INTO address (address_code, state_name, city_name)
VALUES ('05301', '서울특별시', '서대문구');

INSERT INTO user (email, nickname, user_code, role)
VALUES ('say01v@naver.com', 'jji','eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjmFtZSI6IkpvaG4gRG9lIi', 'USER'),
       ('say02v@naver.com', 'j2', 'hytnfgncCI6IkpXVCJ9.eyJzdWIiOiIvsdvnksdnklfsdRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeK', 'USER'),
       ('say03v@naver.com', 'j3', 'sgdsvdsXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5M', 'USER'),
       ('say04v@naver.com', 'j4', 'oloiopitjt5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0Ij', 'USER'),
       ('say05v@naver.com', 'j5', 'nbvnvCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0I', 'USER'),
       ('say06v@naver.com', 'j6', 'hfghJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9l', 'USER'),
       ('say07v@naver.com', 'j7', 'ritrursInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9l', 'USER'),
       ('say08v@naver.com', 'j8', 'lyilhjh.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MD', 'USER');

INSERT INTO accommodation (accommodation_name, address_code, user_id, working_start, working_end , weekend_working_start, weekend_working_end, location, lot_number, address_detail, accommodation_type, average_rate)
VALUES ('정정일 애견 호텔', '05300', 1, '09:00:00', '19:00:00', '11:00:00', '19:00:00', '신림동', '255-11', '행복행복빌 63962호', 0, 1.6),
       ('정정일 애견 유치원', '05300', 1, '09:00:00', '15:00:00', '12:00:00', '15:00:00', '신림동', '255-99', '행복행복빌 23962호', 0, 4.3),
       ('정정일 애묘 호텔', '05300', 1, '09:00:00', '16:00:00', '13:00:00', '16:00:00', '신림동', '255-88', '행복행복빌 33962호', 0, 4.4),
       ('정정일 애묘 유치원', '05300', 1, '09:00:00', '20:00:00', '14:00:00', '20:00:00', '신림동', '255-77', '행복행복빌 43962호', 0, 4.9);

INSERT INTO room (accommodation_id, room_name, amount, pet_category, weight)
VALUES (1, '애견 호텔 5KG 이하', 30000, 'DOG', 5),
       (1, '애견 호텔 5KG 이상', 50000, 'DOG', 10),
       (2, '애견 유치원 5KG 이하', 20000, 'DOG', 5),
       (2, '애견 유치원 5KG 이상', 40000, 'DOG', 10),
       (3, '애묘 호텔 5KG 이하', 25000, 'CAT', 5),
       (3, '애묘 호텔 5KG 이상', 40000, 'CAT', 10),
       (4, '애묘 유치원 5KG 이하', 40000, 'CAT', 5),
       (4, '애묘 유치원 5KG 이상', 70000, 'CAT', 10);

INSERT INTO reservation (room_id, user_id, check_in_date, check_out_date, amount)
VALUES (1, 2, '2022-11-21 14:00:00', '2022-11-25 20:15:00', 100000),
       (1, 3, '2022-11-21 14:00:00', '2022-11-23 16:00:00', 110000),
       (1, 4, '2022-11-21 14:00:00', '2022-11-23 16:00:00', 120000),
       (1, 5, '2022-01-21 14:00:00', '2022-01-23 16:00:00', 130000),
       (2, 5, '2022-02-21 14:00:00', '2022-02-23 16:00:00', 140000),
       (3, 5, '2022-03-21 14:00:00', '2022-03-23 16:00:00', 150000),
       (4, 5, '2022-04-21 14:00:00', '2022-04-23 16:00:00', 160000),
       (1, 5, '2022-05-21 14:00:00', '2022-05-23 16:00:00', 170000),
       (1, 5, '2022-06-21 14:00:00', '2022-06-23 16:00:00', 180000),
       (2, 5, '2022-07-21 14:00:00', '2022-07-23 16:00:00', 190000),
       (2, 5, '2023-12-21 14:00:00', '2023-12-23 16:00:00', 200000),
       (4, 1, '2022-12-22 13:00:00', '2023-12-24 17:00:00', 120000),
       (4, 2, '2022-12-22 13:00:00', '2023-12-24 17:00:00', 120000),
       (4, 3, '2022-12-22 13:00:00', '2023-12-24 17:00:00', 120000),
       (5, 1, '2022-12-22 13:00:00', '2023-12-24 17:00:00', 120000),
       (5, 2, '2022-12-22 13:00:00', '2023-12-24 17:00:00', 120000),
       (5, 3, '2022-12-22 13:00:00', '2023-12-24 17:00:00', 120000),
       (6, 1, '2022-12-22 13:00:00', '2023-12-24 17:00:00', 120000),
       (6, 2, '2022-12-22 13:00:00', '2023-12-24 17:00:00', 120000),
       (6, 3, '2022-12-22 13:00:00', '2023-12-24 17:00:00', 120000),
       (7, 1, '2022-12-22 13:00:00', '2023-12-24 17:00:00', 120000),
       (7, 2, '2022-12-22 13:00:00', '2023-12-24 17:00:00', 120000),
       (7, 3, '2022-12-22 13:00:00', '2023-12-24 17:00:00', 120000),
       (8, 1, '2022-12-22 13:00:00', '2023-12-24 17:00:00', 120000),
       (8, 2, '2022-12-22 13:00:00', '2023-12-24 17:00:00', 120000),
       (8, 3, '2022-12-22 13:00:00', '2023-12-24 17:00:00', 120000),
       (9, 1, '2022-12-22 13:00:00', '2023-12-24 17:00:00', 120000),
       (9, 1, '2022-12-22 13:00:00', '2023-12-24 17:00:00', 120000),
       (9, 1, '2022-12-22 13:00:00', '2023-12-24 17:00:00', 120000),
       (10, 1, '2022-12-22 13:00:00', '2023-12-24 17:00:00', 120000),
       (10, 2, '2022-12-22 13:00:00', '2023-12-24 17:00:00', 120000),
       (10, 3, '2022-12-22 13:00:00', '2023-12-24 17:00:00', 120000),
       (11, 1, '2022-12-22 13:00:00', '2023-12-24 17:00:00', 120000),
       (11, 2, '2022-12-22 13:00:00', '2023-12-24 17:00:00', 120000),
       (11, 3, '2022-12-22 13:00:00', '2023-12-24 17:00:00', 120000),
       (12, 1, '2022-12-22 13:00:00', '2023-12-24 17:00:00', 120000),
       (12, 2, '2022-12-22 13:00:00', '2023-12-24 17:00:00', 120000),
       (12, 3, '2022-12-22 13:00:00', '2023-12-24 17:00:00', 120000),
       (13, 1, '2022-12-22 13:00:00', '2023-12-24 17:00:00', 120000),
       (13, 2, '2022-12-22 13:00:00', '2023-12-24 17:00:00', 120000),
       (13, 3, '2022-12-22 13:00:00', '2023-12-24 17:00:00', 120000),
       (14, 1, '2022-12-22 13:00:00', '2023-12-24 17:00:00', 120000),
       (14, 2, '2022-12-22 13:00:00', '2023-12-24 17:00:00', 120000),
       (14, 3, '2022-12-22 13:00:00', '2023-12-24 17:00:00', 120000),
       (15, 1, '2022-12-22 13:00:00', '2023-12-24 17:00:00', 120000),
       (15, 2, '2022-12-22 13:00:00', '2023-12-24 17:00:00', 120000),
       (15, 3, '2022-12-22 13:00:00', '2023-12-24 17:00:00', 120000),
       (16, 1, '2022-12-22 13:00:00', '2023-12-24 17:00:00', 120000),
       (16, 2, '2022-12-22 13:00:00', '2023-12-24 17:00:00', 120000),
       (16, 3, '2022-12-22 13:00:00', '2023-12-24 17:00:00', 120000),
       (17, 1, '2022-12-22 13:00:00', '2023-12-24 17:00:00', 120000),
       (17, 2, '2022-12-22 13:00:00', '2023-12-24 17:00:00', 120000),
       (17, 3, '2022-12-22 13:00:00', '2023-12-24 17:00:00', 120000),
       (18, 1, '2022-12-22 13:00:00', '2023-12-24 17:00:00', 120000),
       (18, 2, '2022-12-22 13:00:00', '2023-12-24 17:00:00', 120000),
       (18, 3, '2022-12-22 13:00:00', '2023-12-24 17:00:00', 120000),
       (19, 1, '2022-12-22 13:00:00', '2023-12-24 17:00:00', 120000),
       (19, 2, '2022-12-22 13:00:00', '2023-12-24 17:00:00', 120000),
       (19, 3, '2022-12-22 13:00:00', '2023-12-24 17:00:00', 120000),
       (20, 1, '2022-12-22 13:00:00', '2023-12-24 17:00:00', 120000),
       (20, 2, '2022-12-22 13:00:00', '2023-12-24 17:00:00', 120000),
       (20, 3, '2022-12-22 13:00:00', '2023-12-24 17:00:00', 120000),
       (21, 1, '2022-12-22 13:00:00', '2023-12-24 17:00:00', 120000),
       (21, 2, '2022-12-22 13:00:00', '2023-12-24 17:00:00', 120000),
       (21, 3, '2022-12-22 13:00:00', '2023-12-24 17:00:00', 120000),
       (22, 1, '2022-12-22 13:00:00', '2023-12-24 17:00:00', 120000),
       (22, 2, '2022-12-22 13:00:00', '2023-12-24 17:00:00', 120000),
       (22, 3, '2022-12-22 13:00:00', '2023-12-24 17:00:00', 120000),
       (23, 1, '2022-12-22 13:00:00', '2023-12-24 17:00:00', 120000),
       (23, 2, '2022-12-22 13:00:00', '2023-12-24 17:00:00', 120000),
       (23, 3, '2022-12-22 13:00:00', '2023-12-24 17:00:00', 120000),
       (24, 1, '2022-12-22 13:00:00', '2023-12-24 17:00:00', 120000),
       (24, 2, '2022-12-22 13:00:00', '2023-12-24 17:00:00', 120000),
       (24, 3, '2022-12-22 13:00:00', '2023-12-24 17:00:00', 120000),
       (25, 1, '2022-12-22 13:00:00', '2023-12-24 17:00:00', 120000),
       (25, 2, '2022-12-22 13:00:00', '2023-12-24 17:00:00', 120000),
       (25, 3, '2022-12-22 13:00:00', '2023-12-24 17:00:00', 120000),
       (26, 1, '2022-12-22 13:00:00', '2023-12-24 17:00:00', 120000),
       (26, 2, '2022-12-22 13:00:00', '2023-12-24 17:00:00', 120000),
       (26, 3, '2022-12-22 13:00:00', '2023-12-24 17:00:00', 120000),
       (27, 1, '2022-12-22 13:00:00', '2023-12-24 17:00:00', 120000),
       (27, 2, '2022-12-22 13:00:00', '2023-12-24 17:00:00', 120000),
       (27, 3, '2022-12-22 13:00:00', '2023-12-24 17:00:00', 120000),
       (28, 1, '2022-12-22 13:00:00', '2023-12-24 17:00:00', 120000),
       (28, 2, '2022-12-22 13:00:00', '2023-12-24 17:00:00', 120000),
       (28, 3, '2022-12-22 13:00:00', '2023-12-24 17:00:00', 120000),
       (29, 1, '2022-12-22 13:00:00', '2023-12-24 17:00:00', 120000),
       (29, 2, '2022-12-22 13:00:00', '2023-12-24 17:00:00', 120000),
       (29, 3, '2022-12-22 13:00:00', '2023-12-24 17:00:00', 120000),
       (30, 1, '2022-12-22 13:00:00', '2023-12-24 17:00:00', 120000),
       (30, 2, '2022-12-22 13:00:00', '2023-12-24 17:00:00', 120000),
       (30, 3, '2022-12-22 13:00:00', '2023-12-24 17:00:00', 120000);

INSERT INTO review (user_id, reservation_id, rate, content)
VALUES (3, 2, 5, 'very good'),
       (5, 4, 5, 'good'),
       (5, 5, 4, 'good good'),
       (5, 6, 3, 'not bad'),
       (5, 7, 1, 'very bad'),
       (5, 8, 5, 'very very good'),
       (5, 9, 4, 'good'),
       (5, 10, 5, 'wonderful'),
       (1, 12, 5, '아주 만족해요 ㅎㅎ'),
       (2, 13, 5, '사장님이 친절해요'),
       (3, 14, 5, '친절한 사장님 감사합니다'),
       (1, 15, 5, '자주 애용합니다 아주 좋아요'),
       (2, 16, 5, '덕분에 마음편히 여행 다녀왔습니다'),
       (3, 17, 5, '아주 강추드려요'),
       (1, 18, 5, null),
       (2, 19, 5, '저는 만족요'),
       (3, 20, 5, '안심하고 여행다녀왔어요'),
       (1, 21, 5, '만족 그자체'),
       (2, 22, 5, '사랑합니다'),
       (3, 23, 5, '감사합니다'),
       (1, 24, 5, '친절함에 치여요'),
       (2, 25, 5, '아주 좋네요'),
       (3, 26, 5, null),
       (1, 27, 5, null),
       (2, 28, 5, '5점 만점에 만점'),
       (3, 29, 5, '저의 희망'),
       (1, 30, 5, '애용할 수 밖에 없어요'),
       (2, 31, 5, '여행가기전 필수 예약'),
       (3, 32, 5, '아이들이 다녀오면 행복해 해요'),
       (1, 33, 5, '사회화 교육도 잘 진행되는 것 같습니다'),
       (2, 34, 5, '애기들이 더 좋아해요'),
       (3, 35, 5, '여기 가는걸 애기들이 기대해요'),
       (1, 36, 5, '마음편히 여행 다녀올 수 있네요 ㅎㅎ'),
       (2, 37, 5, '5점 드릴 수 밖에 없네요'),
       (3, 38, 5, '사장님이 매우 친절합니다'),
       (1, 39, 5, '기가 막혀요'),
       (2, 40, 5, '코도 막혀요'),
       (3, 41, 5, '굉장합니다'),
       (1, 42, 5, '친절해요'),
       (2, 43, 5, '감사합니다'),
       (3, 44, 5, '나쁘지 않아요'),
       (1, 45, 5, '아주 만족스럽습니다'),
       (2, 46, 5, '굉장하네요 ㅎㅎ'),
       (3, 47, 5, '환경이 너무 깨끗해요'),
       (1, 48, 5, '좋네요'),
       (2, 49, 5, '그저 빛'),
       (1, 51, 5, '빛'),
       (2, 52, 5, '빛 그자체'),
       (3, 53, 5, '감사합니다'),
       (1, 54, 5, '매우 친절해요'),
       (2, 55, 5, '너무 만족스럽습니다'),
       (3, 56, 4, '나쁘지 않았습니다'),
       (1, 57, 3, '그저 그래요'),
       (2, 58, 1, '별로입니다'),
       (3, 59, 5, '환상적이에요'),
       (1, 60, 4, '사장님이 친절해요'),
       (2, 61, 3, '평범합니다'),
       (3, 62, 1, '다시는 안갈래요'),
       (1, 63, 5, '너무 만족스럽습니다!!'),
       (2, 64, 5, '꼭 가보세요!'),
       (3, 65, 5, '고민중이시라면 무조건 가봐야합니다'),
       (1, 66, 5, '별점 5점도 낮은거같아요 100점 드리고 싶어요!'),
       (2, 67, 5, '아이들이 너무 좋아해요'),
       (3, 68, 5, '애기들이 다녀오면 아주 잘자요'),
       (1, 69, 5, '저희 집보다 환경이 좋은거 같습니'),
       (2, 70, 5, '아주 만족해요!'),
       (3, 71, 3, '그저 그렇습니다'),
       (1, 72, 5, '여기만큼 좋은 곳은 못봤어요'),
       (2, 73, 5, '사장님이 아주 친절하십니다!'),
       (3, 74, 5, '세상에 세상에 꼭 다시 아이들 보내고 싶어요!'),
       (1, 75, 5, '예약하기 힘들었는데 드디어 했네요! 아주 만족합니다!'),
       (2, 76, 5, '사장님이 친절해요'),
       (3, 77, 5, '좋네요'),
       (1, 78, 5, '굿굿'),
       (2, 79, 5, '5점드립니다'),
       (3, 80, 5, '5점 만점에 100점!'),
       (1, 81, 5, '꼭 다시 연락 드리고 싶습니다'),
       (2, 82, 5, '아이들이 행복해해요'),
       (3, 83, 5, '이게 애견 호텔이죠'),
       (1, 84, 5, '너무 좋습니다'),
       (2, 85, 5, '아주 좋아요'),
       (3, 86, 5, '좋네요'),
       (1, 87, 5, '좋습니다'),
       (2, 88, 5, '괜찮아요'),
       (3, 89, 5, '만족해요!'),
       (1, 90, 5, '행복합니다'),
       (2, 91, 5, '감사해요!'),
       (3, 92, 5, '완전 좋아요');

INSERT INTO bookmark(user_id, accommodation_id, state)
VALUES (5, 1, false),
       (5, 2, false),
       (5, 3, true);

INSERT INTO image_file(url)
VALUES ('testurl1'),
       ('testurl2'),
       ('testurl3'),
       ('testurl4'),
       ('testurl5');

INSERT INTO file(accommodation_id, room_id, image_file_id)
VALUES (1, null, 1),
       (1, null, 2),
       (1, null, 3),
       (1, null, 4),
       (1, null, 5);