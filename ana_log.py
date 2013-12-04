
inserts = 0
selects = 0
commits = 0
updates = 0

with open('sqlalchemy.log') as f:
    data = f.readlines()

for line in data:
    if 'INSERT' in line:
        inserts += 1
    elif 'SELECT' in line:
        selects += 1
    elif 'COMMIT' in line:
        commits += 1
    elif 'UPDATE' in line:
        updates += 1

print("Inserts: {}".format(inserts))
print("Updates: {}".format(updates))
print("Selects: {}".format(selects))
print("Commits: {}".format(commits))
