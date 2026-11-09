-- N빵 정산기 실시간 공유용 스키마
-- Supabase 대시보드 > SQL Editor 에 붙여넣고 Run. 여러 번 실행해도 안전하다.
--
-- 보안 모델: 공유방 ID(추측 불가능한 22자 난수)를 아는 사람만 그 방을 읽고 쓴다.
-- 앱은 모든 요청에 x-room-id 헤더를 보내고, RLS 정책이 그 헤더와 같은 방의 행만 허용한다.
-- 헤더 없이 요청하면 아무 행도 보이지 않으므로 다른 방 목록을 훑어볼 수 없다.

create table if not exists public.rooms (
  id text primary key check (char_length(id) between 20 and 40),
  title text not null default '' check (char_length(title) <= 100),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.people (
  room_id text not null references public.rooms(id) on delete cascade,
  id text not null check (char_length(id) between 1 and 20),
  name text not null check (char_length(name) between 1 and 40),
  color text not null check (color ~ '^#[0-9a-f]{6}$'),
  pos double precision not null default 0,
  primary key (room_id, id)
);

create table if not exists public.expenses (
  room_id text not null references public.rooms(id) on delete cascade,
  id text not null check (char_length(id) between 1 and 20),
  name text not null default '' check (char_length(name) <= 100),
  amount bigint not null check (amount between 0 and 1000000000000),
  payer text not null default '' check (char_length(payer) <= 20),
  members text[] not null default '{}' check (cardinality(members) <= 100),
  pos double precision not null default 0,
  primary key (room_id, id)
);

-- 요청 헤더의 방 ID (없으면 null → 어떤 행과도 일치하지 않음)
create or replace function public.request_room() returns text
language sql stable set search_path = '' as $$
  select nullif(coalesce(nullif(current_setting('request.headers', true), ''), '{}')::json ->> 'x-room-id', '')
$$;

-- 방 안의 행이 바뀌면 rooms.updated_at 을 갱신 (앱이 이 값으로 변경 여부를 확인)
-- 한 방에 참여자 100명, 금액 1,000건까지만 허용
-- security definer: anon 은 rooms.title 만 수정할 수 있으므로 updated_at 갱신은 소유자 권한으로 한다.
-- 대상 방(rid)은 이미 RLS 를 통과한 행에서 가져온 값이다.
create or replace function public.touch_room() returns trigger
language plpgsql security definer set search_path = '' as $$
declare rid text;
begin
  if tg_op = 'DELETE' then rid := old.room_id; else rid := new.room_id; end if;
  if tg_op = 'INSERT' then
    if tg_table_name = 'people' and (select count(*) from public.people where room_id = rid) > 100 then
      raise exception 'too many people';
    end if;
    if tg_table_name = 'expenses' and (select count(*) from public.expenses where room_id = rid) > 1000 then
      raise exception 'too many expenses';
    end if;
  end if;
  update public.rooms set updated_at = now() where id = rid;
  return null;
end $$;

create or replace function public.rooms_touch() returns trigger
language plpgsql set search_path = '' as $$
begin new.updated_at := now(); return new; end $$;

drop trigger if exists people_touch on public.people;
create trigger people_touch after insert or update or delete on public.people
  for each row execute function public.touch_room();
drop trigger if exists expenses_touch on public.expenses;
create trigger expenses_touch after insert or update or delete on public.expenses
  for each row execute function public.touch_room();
drop trigger if exists rooms_touch on public.rooms;
create trigger rooms_touch before update on public.rooms
  for each row execute function public.rooms_touch();

alter table public.rooms enable row level security;
alter table public.people enable row level security;
alter table public.expenses enable row level security;

-- 방 자체는 만들고 읽고 제목만 고칠 수 있다 (삭제 불가)
drop policy if exists rooms_select on public.rooms;
drop policy if exists rooms_insert on public.rooms;
drop policy if exists rooms_update on public.rooms;
create policy rooms_select on public.rooms for select to anon using (id = public.request_room());
create policy rooms_insert on public.rooms for insert to anon with check (id = public.request_room());
create policy rooms_update on public.rooms for update to anon using (id = public.request_room()) with check (id = public.request_room());

drop policy if exists people_rw on public.people;
create policy people_rw on public.people for all to anon
  using (room_id = public.request_room()) with check (room_id = public.request_room());
drop policy if exists expenses_rw on public.expenses;
create policy expenses_rw on public.expenses for all to anon
  using (room_id = public.request_room()) with check (room_id = public.request_room());

revoke all on public.rooms, public.people, public.expenses from anon, authenticated;
grant select, insert (id, title), update (title) on public.rooms to anon;
revoke execute on function public.touch_room() from public, anon, authenticated;
grant select, insert, update, delete on public.people, public.expenses to anon;
grant execute on function public.request_room() to anon;
