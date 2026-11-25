import { useState } from 'react'
import { Page } from '@/components/layout/Page'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { useAuthStore } from '@/stores/authStore'
import { AppearanceTab } from './AppearanceTab'
import { ProfileTab } from './ProfileTab'
import { UsersTab } from './UsersTab'

export function SettingsPage() {
  const role = useAuthStore((s) => s.user?.role)
  // /users needs the users:read permission, which only the admin role has.
  const isAdmin = role === 'admin'
  const [tab, setTab] = useState('profile')

  return (
    <Page title="Settings" description="Your account, users and appearance">
      <Tabs value={tab} onValueChange={setTab}>
        <TabsList>
          <TabsTrigger value="profile">Profile and security</TabsTrigger>
          {isAdmin && <TabsTrigger value="users">Users</TabsTrigger>}
          <TabsTrigger value="appearance">Appearance</TabsTrigger>
        </TabsList>
        <TabsContent value="profile" className="mt-4"><ProfileTab /></TabsContent>
        {isAdmin && <TabsContent value="users" className="mt-4"><UsersTab /></TabsContent>}
        <TabsContent value="appearance" className="mt-4"><AppearanceTab /></TabsContent>
      </Tabs>
    </Page>
  )
}
