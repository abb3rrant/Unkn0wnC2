const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const page = fs.readFileSync('web/users.html', 'utf8');
const start = page.indexOf('async function updateUser(');
const end = page.indexOf('// Change password', start);
assert(start >= 0 && end > start);
const source = page.slice(start, end);
(async () => {
    for (const role of ['viewer', 'operator', 'admin']) {
        let sent;
        let closed = false;
        const elements = {
            editUserId: {value:'fixture-id'}, editUsername:{value:'updated-name'},
            editRole:{value:role}, editEmail:{value:'fixture@example.invalid'},
            editError:{style:{}}
        };
        const context = vm.createContext({
            currentUserRole:role,
            document:{getElementById:id=>elements[id]},
            authFetch:async (url, options) => { sent={url,body:JSON.parse(options.body)}; return {json:async()=>({success:true})}; },
            closeEditModal:()=>{closed=true;},loadUsers:()=>{}
        });
        vm.runInContext(source,context);
        await vm.runInContext('updateUser({preventDefault(){}})',context);
        assert.equal(sent.url,'/api/operators/fixture-id');
        assert.equal(sent.body.username,'updated-name');
        assert.equal(sent.body.email,'fixture@example.invalid');
        if (role === 'admin') assert.equal(sent.body.role,'admin');
        else assert(!Object.hasOwn(sent.body,'role'),`${role} self-edit attempted to submit a role`);
        assert(closed,`${role} successful edit did not close`);
    }
    console.log('viewer/operator omit role; admin role edits preserved');
})().catch(error=>{console.error(error.message);process.exitCode=1;});
