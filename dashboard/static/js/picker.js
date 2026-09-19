document.addEventListener('DOMContentLoaded', async () => {
    await fetchAndRenderEngagements();

    document.getElementById('modal-close').addEventListener('click', closeMetaModal);
    document.getElementById('meta-form').addEventListener('submit', handleMetaSubmit);
    document.getElementById('new-engagement-form').addEventListener('submit', handleNewEngagement);

    // Close modal if clicking outside
    document.getElementById('meta-modal').addEventListener('click', (e) => {
        if (e.target.id === 'meta-modal') closeMetaModal();
    });
});

async function handleNewEngagement(e) {
    e.preventDefault();
    const btn = e.target.querySelector('button');
    const target = document.getElementById('new-target').value.trim();
    if (!target) return;

    btn.textContent = 'Creating...';
    btn.disabled = true;

    try {
        const resp = await fetch('/api/engagements', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                target: target,
                name: document.getElementById('new-name').value.trim(),
                methodology: document.getElementById('new-methodology').value,
            })
        });
        const data = await resp.json();
        if (data.engagement_name) {
            // Set cookie and navigate to dashboard
            document.cookie = `active_engagement=${data.engagement_name}; path=/; max-age=86400`;
            window.location.href = '/';
        } else {
            throw new Error(data.detail || 'Failed to create engagement');
        }
    } catch (err) {
        alert('Error: ' + err.message);
        btn.textContent = '+ New Engagement';
        btn.disabled = false;
    }
}

async function fetchAndRenderEngagements() {
    const wrapper = document.getElementById('engagements-wrapper');
    try {
        const resp = await fetch('/api/engagements');
        const data = await resp.json();
        const engagements = data.engagements || [];

        if (engagements.length === 0) {
            wrapper.innerHTML = '<div class="placeholder">No engagements found on disk.</div>';
            return;
        }

        // Group by group_name
        const groups = {};
        engagements.forEach(eng => {
            const g = eng.group_name || 'Default';
            if (!groups[g]) groups[g] = [];
            groups[g].push(eng);
        });

        wrapper.innerHTML = '';

        // Sort groups alphabetically, but keep Default at the end
        const groupNames = Object.keys(groups).sort((a, b) => {
            if (a === 'Default') return 1;
            if (b === 'Default') return -1;
            return a.localeCompare(b);
        });

        groupNames.forEach(gName => {
            const section = document.createElement('div');
            section.className = 'group-section';
            
            const title = document.createElement('h2');
            title.className = 'group-title';
            title.textContent = gName;
            section.appendChild(title);

            const grid = document.createElement('div');
            grid.className = 'card-grid';

            groups[gName].forEach(eng => {
                const card = document.createElement('div');
                card.className = 'engagement-card';
                
                // Allow clicking the card to enter the dashboard
                card.onclick = (e) => {
                    // Prevent navigation if clicking the edit button
                    if(e.target.closest('.edit-btn')) return;
                    
                    document.cookie = `active_engagement=${eng.name}; path=/; max-age=86400`;
                    window.location.href = '/';
                };

                const editBtn = document.createElement('button');
                editBtn.className = 'edit-btn';
                editBtn.innerHTML = '&#9998;';
                editBtn.title = 'Edit Metadata';
                editBtn.onclick = (e) => {
                    e.stopPropagation();
                    openMetaModal(eng);
                };
                card.appendChild(editBtn);

                const nameDiv = document.createElement('div');
                nameDiv.className = 'eng-name';
                nameDiv.textContent = eng.name;
                card.appendChild(nameDiv);

                const targetDiv = document.createElement('div');
                targetDiv.className = 'eng-target';
                targetDiv.textContent = 'TARGET: ' + eng.target;
                card.appendChild(targetDiv);

                const tagsDiv = document.createElement('div');
                tagsDiv.className = 'tags-container';
                const tags = eng.tags || [];
                if (tags.length === 0) {
                    const tag = document.createElement('span');
                    tag.className = 'tag-pill';
                    tag.textContent = 'no-tags';
                    tag.style.opacity = '0.5';
                    tagsDiv.appendChild(tag);
                } else {
                    tags.forEach(t => {
                        const tag = document.createElement('span');
                        tag.className = 'tag-pill';
                        tag.textContent = t;
                        tagsDiv.appendChild(tag);
                    });
                }
                card.appendChild(tagsDiv);

                grid.appendChild(card);
            });

            section.appendChild(grid);
            wrapper.appendChild(section);
        });

    } catch (e) {
        wrapper.innerHTML = `<div class="placeholder" style="color:var(--red)">Error loading engagements: ${e.message}</div>`;
    }
}

function openMetaModal(eng) {
    document.getElementById('edit-eng-name').value = eng.name;
    document.getElementById('edit-group').value = eng.group_name === 'Default' ? '' : eng.group_name;
    document.getElementById('edit-tags').value = (eng.tags || []).join(', ');
    document.getElementById('meta-modal').classList.remove('hidden');
    document.getElementById('edit-group').focus();
}

function closeMetaModal() {
    document.getElementById('meta-modal').classList.add('hidden');
}

async function handleMetaSubmit(e) {
    e.preventDefault();
    const btn = e.target.querySelector('button');
    btn.textContent = 'Saving...';
    btn.disabled = true;

    const engName = document.getElementById('edit-eng-name').value;
    const group = document.getElementById('edit-group').value.trim() || 'Default';

    // Parse tags safely, stripping empty tags and trim spaces
    const tagsRaw = document.getElementById('edit-tags').value;
    const tags = tagsRaw.split(',')
        .map(t => t.trim())
        .filter(t => t.length > 0);

    try {
        const resp = await fetch(`/api/engagement/${engName}/meta`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ group_name: group, tags: tags })
        });

        if (!resp.ok) {
            throw new Error('Failed to update');
        }

        closeMetaModal();
        await fetchAndRenderEngagements();
    } catch (err) {
        alert('Error saving metadata: ' + err.message);
    } finally {
        btn.textContent = 'Save Changes';
        btn.disabled = false;
    }
}
